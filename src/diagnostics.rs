use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::backup::{self, BackupError};
use crate::config::Config;
use crate::git::repository::{GitRepository, GitRepositoryError};
use crate::instance::REPOSITORY_DIRECTORY;
use crate::serve::{self, ServeError};
use crate::store::{
    AccountInspection, DATABASE_FILE, DumpRow, GitIntentInspection, RepositoryInspection, Store,
    StoreError,
};

const REQUIRED_INDEXES: &[&str] = &[
    "audit_event_correlation",
    "audit_event_history",
    "feed_token_account_active",
    "feed_token_repository_active",
    "git_operation_intent_incomplete",
    "issue_comment_history",
    "issue_repository_state",
    "login_nonce_active",
    "m1a_child_state_parent",
    "m1a_parent_created_at",
    "pull_request_ref_intent_incomplete",
    "pull_request_repository_state",
    "pull_request_review_status",
    "pull_request_review_timeline",
    "pull_request_revision_history",
    "repository_collaborator_account",
    "repository_event_feed",
    "repository_event_issue_timeline",
    "repository_event_pull_request_timeline",
    "signup_invitation_active",
    "ssh_public_key_account",
    "watch_account_activity",
    "web_session_account_active",
];

pub(crate) fn doctor(config: &Config, backups: &[PathBuf]) -> Result<(), DiagnosticError> {
    check_private_directory(&config.instance_dir)?;
    check_private_file(&config.config_path)?;
    let database = config.instance_dir.join(DATABASE_FILE);
    check_private_file(&database)?;
    crate::store::doctor(&config.instance_dir)?;

    let store = Store::open_read_only(&database)?;
    let indexes: HashSet<_> = store.index_names()?.into_iter().collect();
    for required in REQUIRED_INDEXES {
        if !indexes.contains(*required) {
            return Err(DiagnosticError::MissingIndex((*required).to_owned()));
        }
    }
    let git_intents = store.incomplete_git_intents()?;
    let pull_request_intents = store.incomplete_pull_request_ref_intents()?;
    if !git_intents.is_empty() || !pull_request_intents.is_empty() {
        return Err(DiagnosticError::IncompleteIntents {
            git: git_intents.len(),
            pull_request: pull_request_intents.len(),
        });
    }
    check_repositories(&config.instance_dir, &store)?;
    serve::check_host_key(&config.instance_dir)?;
    for archive in backups {
        backup::check_archive(archive)?;
    }
    Ok(())
}

pub(crate) fn inspect_account(
    config: &Config,
    username: &str,
) -> Result<AccountInspection, DiagnosticError> {
    let store = Store::open_read_only(&config.instance_dir.join(DATABASE_FILE))?;
    Ok(store.inspect_account(username)?)
}

pub(crate) fn inspect_repository(
    config: &Config,
    owner: &str,
    slug: &str,
) -> Result<RepositoryInspection, DiagnosticError> {
    let store = Store::open_read_only(&config.instance_dir.join(DATABASE_FILE))?;
    let repository = store.repository(owner, slug)?;
    let default_branch = store.repository_default_branch(owner, slug)?;
    check_repository(&config.instance_dir, &repository, &default_branch)?;
    Ok(repository.into())
}

pub(crate) fn inspect_intent(
    config: &Config,
    id: &str,
) -> Result<GitIntentInspection, DiagnosticError> {
    let store = Store::open_read_only(&config.instance_dir.join(DATABASE_FILE))?;
    Ok(store.inspect_git_intent(id)?)
}

pub(crate) fn dump(
    config: &Config,
    visit: impl FnMut(DumpRow) -> bool,
) -> Result<(), DiagnosticError> {
    let store = Store::open_read_only(&config.instance_dir.join(DATABASE_FILE))?;
    Ok(store.dump_rows(visit)?)
}

fn check_repositories(instance_dir: &Path, store: &Store) -> Result<(), DiagnosticError> {
    let root = instance_dir.join(REPOSITORY_DIRECTORY);
    check_private_directory(&root)?;
    let repositories = store.all_repositories()?;
    let expected: HashSet<_> = repositories
        .iter()
        .map(|repository| format!("{}.git", repository.id))
        .collect();
    for repository in &repositories {
        let default_branch =
            store.repository_default_branch(&repository.owner, &repository.slug)?;
        check_repository(instance_dir, repository, &default_branch)?;
    }
    for entry in fs::read_dir(&root).map_err(|source| DiagnosticError::Io {
        path: root.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| DiagnosticError::Io {
            path: root.clone(),
            source,
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(DiagnosticError::UnknownRepositoryEntry(entry.path()));
        };
        if !expected.contains(&name) {
            return Err(DiagnosticError::UnknownRepositoryEntry(entry.path()));
        }
    }
    Ok(())
}

fn check_repository(
    instance_dir: &Path,
    repository: &crate::store::RepositoryRecord,
    default_branch: &str,
) -> Result<(), DiagnosticError> {
    let path = instance_dir
        .join(REPOSITORY_DIRECTORY)
        .join(format!("{}.git", repository.id));
    let metadata = fs::symlink_metadata(&path).map_err(|source| DiagnosticError::Io {
        path: path.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(DiagnosticError::UnsafePath(path));
    }
    let git = GitRepository::open(&path)?;
    let format = match git.object_format() {
        gix::hash::Kind::Sha1 => "sha1",
        gix::hash::Kind::Sha256 => "sha256",
        _ => return Err(DiagnosticError::UnsupportedObjectFormat),
    };
    if format != repository.object_format {
        return Err(DiagnosticError::ObjectFormat(repository.id.clone()));
    }
    if git.default_branch()?.as_deref() != Some(default_branch) {
        return Err(DiagnosticError::DefaultBranch(repository.id.clone()));
    }
    git.integrity_check()?;

    let quarantine = path.join("objects").join("tit-quarantine");
    match fs::symlink_metadata(&quarantine) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(DiagnosticError::UnsafePath(quarantine));
            }
            if fs::read_dir(&quarantine)
                .map_err(|source| DiagnosticError::Io {
                    path: quarantine.clone(),
                    source,
                })?
                .next()
                .is_some()
            {
                return Err(DiagnosticError::QuarantineDebris(quarantine));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DiagnosticError::Io {
                path: quarantine,
                source,
            });
        }
    }
    Ok(())
}

fn check_private_directory(path: &Path) -> Result<(), DiagnosticError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| DiagnosticError::Io {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(DiagnosticError::UnsafePath(path.to_owned()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(DiagnosticError::Permissions {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

fn check_private_file(path: &Path) -> Result<(), DiagnosticError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| DiagnosticError::Io {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(DiagnosticError::UnsafePath(path.to_owned()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(DiagnosticError::Permissions {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum DiagnosticError {
    #[error("diagnostic path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("diagnostic path permissions for {path} are {mode:o}, expected owner-only access")]
    Permissions { path: PathBuf, mode: u32 },
    #[error("required database index does not exist: {0}")]
    MissingIndex(String),
    #[error(
        "incomplete intents exist: {git} Git operation intents and {pull_request} pull-request ref intents"
    )]
    IncompleteIntents { git: usize, pull_request: usize },
    #[error("repository directory has an unknown entry: {0}")]
    UnknownRepositoryEntry(PathBuf),
    #[error("repository has quarantine debris: {0}")]
    QuarantineDebris(PathBuf),
    #[error("repository object format does not match its database record: {0}")]
    ObjectFormat(String),
    #[error("repository default branch does not match its database record: {0}")]
    DefaultBranch(String),
    #[error("repository object format is not supported")]
    UnsupportedObjectFormat,
    #[error("diagnostic I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Git(#[from] GitRepositoryError),
    #[error(transparent)]
    HostKey(#[from] ServeError),
    #[error(transparent)]
    Backup(#[from] BackupError),
}
