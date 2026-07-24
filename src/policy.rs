use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::store::{RepositoryAuthorizationRecord, RepositoryRecord, Store, StoreError};

#[derive(Clone)]
pub(crate) struct RepositoryPolicy {
    database: PathBuf,
}

impl RepositoryPolicy {
    pub(crate) fn new(database: &Path) -> Self {
        Self {
            database: database.to_owned(),
        }
    }

    pub(crate) fn authorize(
        &self,
        actor: Option<&str>,
        owner: &str,
        repository: &str,
        operation: RepositoryOperation,
    ) -> Result<RepositoryRecord, PolicyError> {
        let record =
            Store::open(&self.database)?.repository_authorization(owner, repository, actor)?;
        if allows(&record, operation)? {
            Ok(record.repository)
        } else {
            Err(PolicyError::Denied)
        }
    }

    pub(crate) fn authorize_ref_change(
        &self,
        actor: &str,
        owner: &str,
        repository: &str,
        ref_name: &[u8],
        change: RefChange,
    ) -> Result<RepositoryRecord, PolicyError> {
        let store = Store::open(&self.database)?;
        let record = store.repository_authorization(owner, repository, Some(actor))?;
        if !allows(&record, RepositoryOperation::Write)? {
            return Err(PolicyError::Denied);
        }
        let default_branch = store.repository_default_branch(owner, repository)?;
        let protected = ref_name == default_branch.as_bytes();
        if matches!(change, RefChange::Force)
            || (protected && matches!(change, RefChange::Delete))
            || (protected && !allows(&record, RepositoryOperation::Maintain)?)
        {
            return Err(PolicyError::Denied);
        }
        Ok(record.repository)
    }

    pub(crate) fn authorize_merge(
        &self,
        actor: &str,
        owner: &str,
        repository: &str,
    ) -> Result<RepositoryRecord, PolicyError> {
        self.authorize(
            Some(actor),
            owner,
            repository,
            RepositoryOperation::Maintain,
        )
    }

    #[allow(
        dead_code,
        reason = "policy tests verify anonymous catalog behavior independently"
    )]
    pub(crate) fn public_repositories(&self) -> Result<Vec<RepositoryRecord>, PolicyError> {
        Store::open(&self.database)?
            .active_repositories()?
            .into_iter()
            .filter_map(|repository| {
                let record = RepositoryAuthorizationRecord {
                    repository,
                    role: None,
                };
                match allows(&record, RepositoryOperation::Read) {
                    Ok(true) => Some(Ok(record.repository)),
                    Ok(false) => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefChange {
    Create,
    FastForward,
    Force,
    Delete,
    TagUpdate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "subsequent transports use the complete repository operation matrix"
)]
pub(crate) enum RepositoryOperation {
    Read,
    Write,
    Maintain,
    Own,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryRole {
    Owner,
    Maintainer,
    Writer,
    Reader,
}

fn allows(
    record: &RepositoryAuthorizationRecord,
    operation: RepositoryOperation,
) -> Result<bool, PolicyError> {
    if record.repository.state != "active" {
        return Ok(false);
    }
    let role = record.role.as_deref().map(parse_role).transpose()?;
    match operation {
        RepositoryOperation::Read => Ok(record.repository.visibility == "public" || role.is_some()),
        RepositoryOperation::Write => Ok(matches!(
            role,
            Some(RepositoryRole::Owner | RepositoryRole::Maintainer | RepositoryRole::Writer)
        )),
        RepositoryOperation::Maintain => Ok(matches!(
            role,
            Some(RepositoryRole::Owner | RepositoryRole::Maintainer)
        )),
        RepositoryOperation::Own => Ok(role == Some(RepositoryRole::Owner)),
    }
}

fn parse_role(role: &str) -> Result<RepositoryRole, PolicyError> {
    match role {
        "owner" => Ok(RepositoryRole::Owner),
        "maintainer" => Ok(RepositoryRole::Maintainer),
        "writer" => Ok(RepositoryRole::Writer),
        "reader" => Ok(RepositoryRole::Reader),
        _ => Err(PolicyError::InvalidRole),
    }
}

#[derive(Debug, Error)]
pub(crate) enum PolicyError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("repository access is not authorized")]
    Denied,
    #[error("stored repository role is not valid")]
    InvalidRole,
}
