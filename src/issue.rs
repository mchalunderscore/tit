use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::auth::{AuthError, validate_username};
use crate::domain::repository::{RepositoryNameError, validate_slug};
use crate::store::{
    IssueChange, IssueDetail, IssueRecord, NewIssue, RepositoryRecord, Store, StoreError,
};

pub(crate) const MAX_TITLE_BYTES: usize = 200;
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_LABEL_BYTES: usize = 80;

#[derive(Clone)]
pub(crate) struct IssueService {
    database: PathBuf,
}

impl IssueService {
    pub(crate) fn new(database: &Path) -> Self {
        Self {
            database: database.to_owned(),
        }
    }

    pub(crate) fn create(
        &self,
        owner: &str,
        repository: &str,
        actor: &str,
        title: &str,
        body: &str,
    ) -> Result<IssueRecord, IssueError> {
        validate_context(owner, repository, Some(actor))?;
        validate_title(title)?;
        validate_body(body, true)?;
        let mut store = Store::open(&self.database)?;
        store
            .create_issue(&NewIssue {
                owner,
                repository,
                actor,
                title,
                body,
                created_at: timestamp()?,
            })
            .map_err(Into::into)
    }

    pub(crate) fn list(
        &self,
        owner: &str,
        repository: &str,
        actor: Option<&str>,
    ) -> Result<(RepositoryRecord, Vec<IssueRecord>), IssueError> {
        validate_context(owner, repository, actor)?;
        Store::open(&self.database)?
            .issues(owner, repository, actor)
            .map_err(Into::into)
    }

    pub(crate) fn get(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: Option<&str>,
    ) -> Result<IssueDetail, IssueError> {
        validate_context(owner, repository, actor)?;
        validate_number(number)?;
        Store::open(&self.database)?
            .issue_detail(owner, repository, number, actor)
            .map_err(Into::into)
    }

    pub(crate) fn edit(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        title: &str,
        body: &str,
    ) -> Result<(), IssueError> {
        validate_context(owner, repository, Some(actor))?;
        validate_number(number)?;
        validate_title(title)?;
        validate_body(body, true)?;
        Store::open(&self.database)?
            .edit_issue(
                &IssueChange {
                    owner,
                    repository,
                    number,
                    actor,
                    changed_at: timestamp()?,
                },
                title,
                body,
            )
            .map_err(Into::into)
    }

    pub(crate) fn comment(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        body: &str,
    ) -> Result<String, IssueError> {
        validate_context(owner, repository, Some(actor))?;
        validate_number(number)?;
        validate_body(body, false)?;
        Store::open(&self.database)?
            .comment_issue(owner, repository, number, actor, body, timestamp()?)
            .map_err(Into::into)
    }

    pub(crate) fn set_state(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        state: &str,
    ) -> Result<(), IssueError> {
        validate_context(owner, repository, Some(actor))?;
        validate_number(number)?;
        if !matches!(state, "open" | "closed") {
            return Err(IssueError::State);
        }
        Store::open(&self.database)?
            .set_issue_state(owner, repository, number, actor, state, timestamp()?)
            .map_err(Into::into)
    }

    pub(crate) fn set_label(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        label: &str,
        present: bool,
    ) -> Result<(), IssueError> {
        validate_context(owner, repository, Some(actor))?;
        validate_number(number)?;
        validate_label(label)?;
        Store::open(&self.database)?
            .set_issue_label(
                &IssueChange {
                    owner,
                    repository,
                    number,
                    actor,
                    changed_at: timestamp()?,
                },
                label,
                present,
            )
            .map_err(Into::into)
    }

    pub(crate) fn set_assignee(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        assignee: &str,
        present: bool,
    ) -> Result<(), IssueError> {
        validate_context(owner, repository, Some(actor))?;
        validate_number(number)?;
        validate_username(assignee)?;
        Store::open(&self.database)?
            .set_issue_assignee(
                &IssueChange {
                    owner,
                    repository,
                    number,
                    actor,
                    changed_at: timestamp()?,
                },
                assignee,
                present,
            )
            .map_err(Into::into)
    }
}

fn validate_context(owner: &str, repository: &str, actor: Option<&str>) -> Result<(), IssueError> {
    validate_username(owner)?;
    validate_slug(repository)?;
    if let Some(actor) = actor {
        validate_username(actor)?;
    }
    Ok(())
}

fn validate_number(number: i64) -> Result<(), IssueError> {
    if number < 1 {
        return Err(IssueError::Number);
    }
    Ok(())
}

fn validate_title(title: &str) -> Result<(), IssueError> {
    if title.is_empty()
        || title.len() > MAX_TITLE_BYTES
        || title.trim() != title
        || title.chars().any(char::is_control)
    {
        return Err(IssueError::Title);
    }
    Ok(())
}

fn validate_body(body: &str, empty_ok: bool) -> Result<(), IssueError> {
    if body.len() > MAX_BODY_BYTES
        || (!empty_ok && body.trim().is_empty())
        || body
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(IssueError::Body);
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), IssueError> {
    if label.is_empty()
        || label.len() > MAX_LABEL_BYTES
        || label.trim() != label
        || label.chars().any(char::is_control)
    {
        return Err(IssueError::Label);
    }
    Ok(())
}

fn timestamp() -> Result<i64, IssueError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IssueError::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| IssueError::Clock)
}

#[derive(Debug, Error)]
pub(crate) enum IssueError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    RepositoryName(#[from] RepositoryNameError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("issue number is not valid")]
    Number,
    #[error("issue title is not valid")]
    Title,
    #[error("issue body is not valid")]
    Body,
    #[error("issue state is not valid")]
    State,
    #[error("issue label is not valid")]
    Label,
    #[error("system time is not valid")]
    Clock,
}
