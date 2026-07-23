use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use gix::hash::ObjectId;
use rand::TryRng;
use thiserror::Error;

use crate::auth::{AuthError, validate_username};
use crate::domain::repository::{RepositoryNameError, validate_slug};
use crate::git::read::{
    Comparison, ReadCancellation, ReadError, ReadLimits, RepositoryReadService,
};
use crate::git::repository::{GitRepository, GitRepositoryError};
use crate::store::{
    GitOperationIntent, NewPullRequestMerge, NewPullRequestRefIntent, NewPullRequestReview,
    PullRequestDetail, PullRequestRecord, PullRequestRefIntentRecord, PullRequestRevisionRecord,
    Store, StoreError,
};

pub(crate) const MAX_TITLE_BYTES: usize = 200;
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024;
pub(crate) const MAX_REVIEW_BODY_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub(crate) struct PullRequestService {
    database: PathBuf,
    repositories: PathBuf,
    operations: Arc<Mutex<()>>,
}

pub(crate) struct PullRequestComparison {
    pub(crate) detail: PullRequestDetail,
    pub(crate) revision: PullRequestRevisionRecord,
    pub(crate) comparison: Comparison,
}

impl PullRequestService {
    pub(crate) fn new(database: &Path, repositories: &Path) -> Self {
        Self {
            database: database.to_owned(),
            repositories: repositories.to_owned(),
            operations: Arc::new(Mutex::new(())),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "opening a pull request requires its repository, content, and two refs"
    )]
    pub(crate) fn open(
        &self,
        owner: &str,
        repository: &str,
        actor: &str,
        title: &str,
        body: &str,
        base_ref: &str,
        head_ref: &str,
    ) -> Result<PullRequestRecord, PullRequestError> {
        validate_context(owner, repository, actor)?;
        validate_content(title, body)?;
        validate_branch(base_ref)?;
        validate_branch(head_ref)?;
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.recover_inner()?;

        let authorization = Store::open(&self.database)?.repository_authorization(
            owner,
            repository,
            Some(actor),
        )?;
        let path = self.repository_path(&authorization.repository.id)?;
        let git = GitRepository::open(&path)?;
        let base = git.resolve_branch(base_ref)?;
        let head = git.resolve_branch(head_ref)?;
        let intent_id = random_id()?;
        let pull_request_id = random_id()?;
        let created_at = timestamp()?;
        let mut store = Store::open(&self.database)?;
        let intent = store.begin_pull_request_open(&NewPullRequestRefIntent {
            id: &intent_id,
            pull_request_id: &pull_request_id,
            owner,
            repository,
            actor,
            title,
            body,
            base_ref,
            head_ref,
            base_object_id: &base.to_string(),
            head_object_id: &head.to_string(),
            created_at,
        })?;
        crash_point("intent");
        self.apply_intent(&mut store, &git, &intent)?;
        crash_point("completed");
        Ok(store
            .pull_request(owner, repository, intent.pull_request_number, Some(actor))?
            .pull_request)
    }

    pub(crate) fn revise(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
    ) -> Result<PullRequestRecord, PullRequestError> {
        validate_context(owner, repository, actor)?;
        if number < 1 {
            return Err(PullRequestError::Number);
        }
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.recover_inner()?;
        let current = Store::open(&self.database)?
            .pull_request(owner, repository, number, Some(actor))?
            .pull_request;
        let authorization = Store::open(&self.database)?.repository_authorization(
            owner,
            repository,
            Some(actor),
        )?;
        let path = self.repository_path(&authorization.repository.id)?;
        let git = GitRepository::open(&path)?;
        let base = git.resolve_branch(&current.base_ref)?;
        let head = git.resolve_branch(&current.head_ref)?;
        if head.to_string() == current.head_object_id && base.to_string() == current.base_object_id
        {
            return Err(PullRequestError::Unchanged);
        }
        let intent_id = random_id()?;
        let created_at = timestamp()?;
        let mut store = Store::open(&self.database)?;
        let intent = store.begin_pull_request_revision(
            number,
            &NewPullRequestRefIntent {
                id: &intent_id,
                pull_request_id: &current.id,
                owner,
                repository,
                actor,
                title: &current.title,
                body: &current.body,
                base_ref: &current.base_ref,
                head_ref: &current.head_ref,
                base_object_id: &base.to_string(),
                head_object_id: &head.to_string(),
                created_at,
            },
        )?;
        crash_point("intent");
        self.apply_intent(&mut store, &git, &intent)?;
        crash_point("completed");
        Ok(store
            .pull_request(owner, repository, number, Some(actor))?
            .pull_request)
    }

    #[allow(
        dead_code,
        reason = "integration tests and later non-Web callers read pull requests without comparison"
    )]
    pub(crate) fn get(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: Option<&str>,
    ) -> Result<PullRequestDetail, PullRequestError> {
        validate_username(owner)?;
        validate_slug(repository)?;
        if let Some(actor) = actor {
            validate_username(actor)?;
        }
        if number < 1 {
            return Err(PullRequestError::Number);
        }
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.recover_inner()?;
        Store::open(&self.database)?
            .pull_request(owner, repository, number, actor)
            .map_err(Into::into)
    }

    pub(crate) fn compare(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        revision: Option<i64>,
        actor: Option<&str>,
    ) -> Result<PullRequestComparison, PullRequestError> {
        validate_username(owner)?;
        validate_slug(repository)?;
        if let Some(actor) = actor {
            validate_username(actor)?;
        }
        if number < 1 || revision.is_some_and(|number| number < 1) {
            return Err(PullRequestError::Number);
        }
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.recover_inner()?;
        let detail = Store::open(&self.database)?.pull_request(owner, repository, number, actor)?;
        let revision = match revision {
            Some(number) => detail
                .revisions
                .iter()
                .find(|revision| revision.number == number),
            None => detail.revisions.last(),
        }
        .cloned()
        .ok_or(PullRequestError::Revision)?;
        let path = self.repository_path(&detail.repository.id)?;
        let reader = RepositoryReadService::open(&path, ReadLimits::default())?;
        let comparison = reader.comparison(
            parse_id(&revision.base_object_id)?,
            parse_id(&revision.head_object_id)?,
            &ReadCancellation::default(),
        )?;
        Ok(PullRequestComparison {
            detail,
            revision,
            comparison,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "a review action includes its repository, revision, content, and optional line anchor"
    )]
    pub(crate) fn review(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        revision_number: i64,
        actor: &str,
        kind: &str,
        body: &str,
        path: Option<&[u8]>,
        side: Option<&str>,
        line: Option<i64>,
    ) -> Result<String, PullRequestError> {
        validate_context(owner, repository, actor)?;
        if number < 1 || revision_number < 1 {
            return Err(PullRequestError::Number);
        }
        validate_review(kind, body, path, side, line)?;
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.recover_inner()?;
        let detail =
            Store::open(&self.database)?.pull_request(owner, repository, number, Some(actor))?;
        if detail.pull_request.state != "open" {
            return Err(StoreError::PullRequestState.into());
        }
        let revision = detail
            .revisions
            .iter()
            .find(|revision| revision.number == revision_number)
            .ok_or(PullRequestError::Revision)?;
        let commit_object_id = if kind == "line-comment" {
            let path = path.ok_or(PullRequestError::ReviewAnchor)?;
            let side = side.ok_or(PullRequestError::ReviewAnchor)?;
            let line = line.ok_or(PullRequestError::ReviewAnchor)?;
            let path_to_repository = self.repository_path(&detail.repository.id)?;
            let reader = RepositoryReadService::open(&path_to_repository, ReadLimits::default())?;
            let base = parse_id(&revision.base_object_id)?;
            let head = parse_id(&revision.head_object_id)?;
            let comparison = reader.comparison(base, head, &ReadCancellation::default())?;
            let file = comparison
                .files
                .iter()
                .find(|file| file.path == path)
                .filter(|file| !file.binary)
                .ok_or(PullRequestError::ReviewAnchor)?;
            let (commit, exists) = match side {
                "base" => (base, file.old_id.is_some()),
                "head" => (head, file.new_id.is_some()),
                _ => return Err(PullRequestError::ReviewAnchor),
            };
            if !exists {
                return Err(PullRequestError::ReviewAnchor);
            }
            let blob = reader.blob(commit, path, &ReadCancellation::default())?;
            let line_count = if blob.data.is_empty() {
                0
            } else {
                blob.data.split(|byte| *byte == b'\n').count()
                    - usize::from(blob.data.ends_with(b"\n"))
            };
            let line = usize::try_from(line).map_err(|_| PullRequestError::ReviewAnchor)?;
            if line == 0 || line > line_count {
                return Err(PullRequestError::ReviewAnchor);
            }
            Some(commit.to_string())
        } else {
            None
        };
        Store::open(&self.database)?
            .create_pull_request_review(&NewPullRequestReview {
                owner,
                repository,
                number,
                revision: revision_number,
                actor,
                kind,
                body,
                commit_object_id: commit_object_id.as_deref(),
                path,
                side,
                line,
                created_at: timestamp()?,
            })
            .map_err(Into::into)
    }

    pub(crate) fn merge(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        method: &str,
    ) -> Result<PullRequestRecord, PullRequestError> {
        validate_context(owner, repository, actor)?;
        if number < 1 || !matches!(method, "fast-forward" | "merge-commit") {
            return Err(PullRequestError::MergeMethod);
        }
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.recover_inner()?;
        let detail =
            Store::open(&self.database)?.pull_request(owner, repository, number, Some(actor))?;
        if detail.pull_request.state != "open" {
            return Err(StoreError::PullRequestState.into());
        }
        if !detail.can_merge {
            return Err(StoreError::PullRequestDenied.into());
        }
        let revision = detail.revisions.last().ok_or(PullRequestError::Revision)?;
        let path = self.repository_path(&detail.repository.id)?;
        let git = GitRepository::open(&path)?;
        let base = git.resolve_branch(&detail.pull_request.base_ref)?;
        let head = git.resolve_branch(&detail.pull_request.head_ref)?;
        if base.to_string() != revision.base_object_id
            || head.to_string() != revision.head_object_id
        {
            return Err(PullRequestError::StaleRevision);
        }
        let reader = RepositoryReadService::open(&path, ReadLimits::default())?;
        let comparison = reader.comparison(base, head, &ReadCancellation::default())?;
        let intent_id = random_id()?;
        let created_at = timestamp()?;
        let merge_message = format!(
            "Merge pull request #{number} from {}\n\n{}",
            detail.pull_request.head_ref, detail.pull_request.title
        );
        let new_target = match (method, comparison.mergeability) {
            ("fast-forward", crate::git::read::Mergeability::FastForward) => head,
            ("merge-commit", crate::git::read::Mergeability::Clean) => {
                git.prepare_merge_commit(base, head, actor, created_at, &merge_message)?
            }
            _ => return Err(PullRequestError::Mergeability),
        };
        let repository_text = path.to_str().ok_or(PullRequestError::RepositoryPath)?;
        let quarantine = path.join("objects").join("tit-quarantine").join(&intent_id);
        let quarantine_text = quarantine
            .to_str()
            .ok_or(PullRequestError::RepositoryPath)?;
        let initial = serialize_ref(base, &detail.pull_request.base_ref);
        let proposed = serialize_ref(new_target, &detail.pull_request.base_ref);
        let base_text = base.to_string();
        let head_text = head.to_string();
        let new_target_text = new_target.to_string();
        let mut store = Store::open(&self.database)?;
        store.begin_pull_request_merge(
            &NewPullRequestMerge {
                owner,
                repository,
                number,
                revision: revision.number,
                actor,
                method,
                base_ref: &detail.pull_request.base_ref,
                old_target: &base_text,
                head_target: &head_text,
                new_target: &new_target_text,
                created_at,
            },
            &GitOperationIntent {
                id: &intent_id,
                repository_path: repository_text,
                actor,
                initial_refs: &initial,
                proposed_refs: &proposed,
                event_payload: &proposed,
                quarantine_path: quarantine_text,
                created_at,
            },
        )?;
        crash_point("merge-intent");
        if method == "merge-commit" {
            match git.write_merge_commit(base, head, actor, created_at, &merge_message) {
                Ok(written) if written == new_target => {}
                Ok(_) => {
                    store.abandon_git_intent(&intent_id)?;
                    return Err(PullRequestError::NonDeterministicMerge);
                }
                Err(error) => {
                    store.abandon_git_intent(&intent_id)?;
                    return Err(error.into());
                }
            }
        }
        store.mark_git_objects_promoted(&intent_id, None)?;
        crash_point("merge-objects");
        if let Err(error) = git.update_reference_with_log(
            &detail.pull_request.base_ref,
            Some(base),
            new_target,
            "merge pull request",
        ) {
            match git.reference_target(&detail.pull_request.base_ref)? {
                Some(current) if current == new_target => store.complete_git_intent(&intent_id)?,
                _ => store.abandon_git_intent(&intent_id)?,
            }
            return Err(error.into());
        }
        crash_point("merge-ref");
        store.complete_git_intent(&intent_id)?;
        crash_point("merge-completed");
        Ok(store
            .pull_request(owner, repository, number, Some(actor))?
            .pull_request)
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile the service without the Web list route"
    )]
    pub(crate) fn list(
        &self,
        owner: &str,
        repository: &str,
        actor: Option<&str>,
    ) -> Result<(crate::store::RepositoryRecord, Vec<PullRequestRecord>, bool), PullRequestError>
    {
        validate_username(owner)?;
        validate_slug(repository)?;
        if let Some(actor) = actor {
            validate_username(actor)?;
        }
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.recover_inner()?;
        Store::open(&self.database)?
            .pull_requests(owner, repository, actor)
            .map_err(Into::into)
    }

    pub(crate) fn recover(&self) -> Result<(), PullRequestError> {
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::git::receive_pack::recover_incomplete_pushes(&self.database)?;
        self.recover_inner()
    }

    fn recover_inner(&self) -> Result<(), PullRequestError> {
        let mut store = Store::open(&self.database)?;
        for intent in store.incomplete_pull_request_ref_intents()? {
            let path = self.repository_path(&intent.repository_id)?;
            let git = GitRepository::open(&path)?;
            self.recover_intent(&mut store, &git, &intent)?;
        }
        Ok(())
    }

    fn apply_intent(
        &self,
        store: &mut Store,
        git: &GitRepository,
        intent: &PullRequestRefIntentRecord,
    ) -> Result<(), PullRequestError> {
        let name = pull_request_ref(intent.pull_request_number);
        let old = parse_optional_id(intent.old_head_object_id.as_deref())?;
        let head = parse_id(&intent.head_object_id)?;
        if let Err(error) = git.update_reference(&name, old, head) {
            let current = git.reference_target(&name)?;
            if current == Some(head) {
                store.complete_pull_request_ref_intent(&intent.id)?;
                return Ok(());
            }
            if current == old {
                store.abandon_pull_request_ref_intent(&intent.id)?;
                return Err(error.into());
            }
            return Err(PullRequestError::MixedRecovery(intent.id.clone()));
        }
        crash_point("ref");
        store.complete_pull_request_ref_intent(&intent.id)?;
        Ok(())
    }

    fn recover_intent(
        &self,
        store: &mut Store,
        git: &GitRepository,
        intent: &PullRequestRefIntentRecord,
    ) -> Result<(), PullRequestError> {
        let name = pull_request_ref(intent.pull_request_number);
        let old = parse_optional_id(intent.old_head_object_id.as_deref())?;
        let head = parse_id(&intent.head_object_id)?;
        match git.reference_target(&name)? {
            Some(current) if current == head => {
                store.complete_pull_request_ref_intent(&intent.id)?;
            }
            current if current == old => {
                git.update_reference(&name, old, head)?;
                store.complete_pull_request_ref_intent(&intent.id)?;
            }
            _ => return Err(PullRequestError::MixedRecovery(intent.id.clone())),
        }
        Ok(())
    }

    fn repository_path(&self, repository_id: &str) -> Result<PathBuf, PullRequestError> {
        let path = fs::canonicalize(self.repositories.join(format!("{repository_id}.git")))?;
        if path.parent() != Some(self.repositories.as_path()) {
            return Err(PullRequestError::RepositoryPath);
        }
        Ok(path)
    }
}

fn validate_context(owner: &str, repository: &str, actor: &str) -> Result<(), PullRequestError> {
    validate_username(owner)?;
    validate_slug(repository)?;
    validate_username(actor)?;
    Ok(())
}

fn validate_content(title: &str, body: &str) -> Result<(), PullRequestError> {
    if title.is_empty() || title.len() > MAX_TITLE_BYTES || title.contains(['\r', '\n']) {
        return Err(PullRequestError::Title);
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(PullRequestError::Body);
    }
    Ok(())
}

fn validate_branch(name: &str) -> Result<(), PullRequestError> {
    if !name.starts_with("refs/heads/") || name.len() > 1024 || !name.is_ascii() {
        return Err(PullRequestError::Branch);
    }
    Ok(())
}

fn validate_review(
    kind: &str,
    body: &str,
    path: Option<&[u8]>,
    side: Option<&str>,
    line: Option<i64>,
) -> Result<(), PullRequestError> {
    if body.len() > MAX_REVIEW_BODY_BYTES
        || body
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(PullRequestError::ReviewBody);
    }
    match kind {
        "comment" | "changes-requested" if !body.trim().is_empty() => {
            if path.is_none() && side.is_none() && line.is_none() {
                Ok(())
            } else {
                Err(PullRequestError::ReviewAnchor)
            }
        }
        "approved" if path.is_none() && side.is_none() && line.is_none() => Ok(()),
        "line-comment" if !body.trim().is_empty() => {
            let path = path.ok_or(PullRequestError::ReviewAnchor)?;
            if path.is_empty()
                || path.len() > ReadLimits::default().max_path_bytes
                || path.contains(&0)
                || !matches!(side, Some("base" | "head"))
                || line.is_none_or(|line| line < 1)
            {
                return Err(PullRequestError::ReviewAnchor);
            }
            Ok(())
        }
        "comment" | "line-comment" | "approved" | "changes-requested" => {
            Err(PullRequestError::ReviewBody)
        }
        _ => Err(PullRequestError::ReviewKind),
    }
}

fn pull_request_ref(number: i64) -> String {
    format!("refs/pull/{number}/head")
}

fn serialize_ref(id: ObjectId, name: &str) -> Vec<u8> {
    format!("{id} {name}\n").into_bytes()
}

fn parse_id(value: &str) -> Result<ObjectId, PullRequestError> {
    ObjectId::from_hex(value.as_bytes()).map_err(|_| PullRequestError::StoredObjectId)
}

fn parse_optional_id(value: Option<&str>) -> Result<Option<ObjectId>, PullRequestError> {
    value.map(parse_id).transpose()
}

fn random_id() -> Result<String, PullRequestError> {
    let mut bytes = [0_u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PullRequestError::Random)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn timestamp() -> Result<i64, PullRequestError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PullRequestError::Clock)?
        .as_secs()
        .try_into()
        .map_err(|_| PullRequestError::Clock)
}

#[cfg(test)]
fn crash_point(point: &str) {
    if std::env::var("TIT_M5_1_CRASH_AFTER").as_deref() != Ok(point) {
        return;
    }
    let ready = std::env::var_os("TIT_M5_1_READY").expect("read the M5.1 ready path");
    fs::write(ready, point.as_bytes()).expect("write the M5.1 ready file");
    loop {
        std::thread::park();
    }
}

#[cfg(not(test))]
fn crash_point(_point: &str) {}

#[derive(Debug, Error)]
pub(crate) enum PullRequestError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    RepositoryName(#[from] RepositoryNameError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Git(#[from] GitRepositoryError),
    #[error("pull-request title is not valid")]
    Title,
    #[error("pull-request body is too large")]
    Body,
    #[error("pull-request branch name is not valid")]
    Branch,
    #[error("pull-request number is not valid")]
    Number,
    #[error("pull-request revision does not exist")]
    Revision,
    #[error("pull-request review kind is not valid")]
    ReviewKind,
    #[error("pull-request review body is not valid")]
    ReviewBody,
    #[error("pull-request review line anchor is not valid")]
    ReviewAnchor,
    #[error("pull-request merge method is not valid")]
    MergeMethod,
    #[error("pull-request revision is not the current branch state")]
    StaleRevision,
    #[error("pull request cannot use the requested merge method")]
    Mergeability,
    #[error("pull-request merge did not produce a deterministic commit")]
    NonDeterministicMerge,
    #[error("pull-request refs have not changed")]
    Unchanged,
    #[error("stored pull-request object ID is not valid")]
    StoredObjectId,
    #[error("pull-request ref intent {0} has mixed Git and metadata state")]
    MixedRecovery(String),
    #[error("pull-request repository path is not canonical")]
    RepositoryPath,
    #[error("cannot access a pull-request repository: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Read(#[from] ReadError),
    #[error(transparent)]
    ReceivePack(#[from] crate::git::receive_pack::ReceivePackError),
    #[error("cannot create a random pull-request ID")]
    Random,
    #[error("the system clock is before the Unix epoch")]
    Clock,
}
