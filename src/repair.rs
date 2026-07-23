use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::instance::{InstanceError, InstanceLock, REPOSITORY_DIRECTORY};
use crate::pull_request::{PullRequestError, PullRequestService};
use crate::store::{DATABASE_FILE, Store, StoreError};

pub(crate) fn intents(instance_dir: &Path) -> Result<(), RepairError> {
    let _lock = InstanceLock::acquire(instance_dir)?;
    crate::store::doctor(instance_dir)?;
    let database = instance_dir.join(DATABASE_FILE);
    let repositories = instance_dir.join(REPOSITORY_DIRECTORY);
    PullRequestService::new(&database, &repositories).recover()?;
    Ok(())
}

pub(crate) fn quarantine(instance_dir: &Path) -> Result<(), RepairError> {
    let _lock = InstanceLock::acquire(instance_dir)?;
    crate::store::doctor(instance_dir)?;
    let database = instance_dir.join(DATABASE_FILE);
    let store = Store::open_read_only(&database)?;
    if !store.incomplete_git_intents()?.is_empty()
        || !store.incomplete_pull_request_ref_intents()?.is_empty()
    {
        return Err(RepairError::IncompleteIntents);
    }
    let repositories = store.all_repositories()?;
    drop(store);
    for repository in repositories {
        let path = instance_dir
            .join(REPOSITORY_DIRECTORY)
            .join(format!("{}.git", repository.id))
            .join("objects")
            .join("tit-quarantine");
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
                fs::remove_dir_all(&path).map_err(|source| RepairError::Io {
                    path: path.clone(),
                    source,
                })?;
            }
            Ok(_) => return Err(RepairError::UnsafePath(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(RepairError::Io { path, source }),
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum RepairError {
    #[error("repair path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("repair of quarantine debris requires all intents to be complete")]
    IncompleteIntents,
    #[error("repair I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Instance(#[from] InstanceError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    PullRequest(#[from] PullRequestError),
}
