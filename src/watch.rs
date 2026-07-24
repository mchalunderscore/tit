use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::auth::{AuthError, validate_username};
use crate::domain::repository::{RepositoryNameError, validate_slug};
use crate::store::{RepositoryRecord, Store, StoreError, WatchRecord};
use crate::system::unix_timestamp;

#[derive(Clone)]
pub(crate) struct WatchService {
    database: PathBuf,
}

impl WatchService {
    pub(crate) fn new(database: &Path) -> Self {
        Self {
            database: database.to_owned(),
        }
    }

    pub(crate) fn get(
        &self,
        owner: &str,
        repository: &str,
        actor: Option<&str>,
    ) -> Result<(RepositoryRecord, Option<WatchRecord>), WatchError> {
        validate_username(owner)?;
        validate_slug(repository)?;
        if let Some(actor) = actor {
            validate_username(actor)?;
        }
        Store::open(&self.database)?
            .watch(owner, repository, actor)
            .map_err(Into::into)
    }

    pub(crate) fn set(
        &self,
        owner: &str,
        repository: &str,
        actor: &str,
        watching: bool,
    ) -> Result<Option<WatchRecord>, WatchError> {
        validate(owner, repository, actor)?;
        Store::open(&self.database)?
            .set_watch(owner, repository, actor, watching, timestamp()?)
            .map_err(Into::into)
    }
}

fn validate(owner: &str, repository: &str, actor: &str) -> Result<(), WatchError> {
    validate_username(owner)?;
    validate_slug(repository)?;
    validate_username(actor)?;
    Ok(())
}

fn timestamp() -> Result<i64, WatchError> {
    unix_timestamp().ok_or(WatchError::Clock)
}

#[derive(Debug, Error)]
pub(crate) enum WatchError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    RepositoryName(#[from] RepositoryNameError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("system time is not valid")]
    Clock,
}
