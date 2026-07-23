use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gix::hash::Kind;
use rand::TryRng;
use thiserror::Error;

use crate::auth::{AuthError, validate_username};
use crate::domain::repository::{RepositoryNameError, validate_slug};
use crate::git::repository::{GitRepository, GitRepositoryError};
use crate::maintenance::MaintenanceGate;
use crate::store::{
    HomeRepositoryRecord, NewAuditEvent, NewRepository, RepositoryOrigin, RepositoryRecord, Store,
    StoreError,
};

const HOME_REPOSITORY_LIMIT: usize = 20;

#[derive(Clone)]
pub(crate) struct RepositoryService {
    database: PathBuf,
    root: PathBuf,
    maintenance: MaintenanceGate,
}

impl RepositoryService {
    pub(crate) fn new(database: &Path, root: &Path) -> Self {
        Self::new_with_gate(database, root, MaintenanceGate::default())
    }

    pub(crate) fn new_with_gate(
        database: &Path,
        root: &Path,
        maintenance: MaintenanceGate,
    ) -> Self {
        Self {
            database: database.to_owned(),
            root: root.to_owned(),
            maintenance,
        }
    }

    pub(crate) fn create_for_account(
        &self,
        actor: &str,
        slug: &str,
        object_format: Kind,
        correlation_id: &str,
    ) -> Result<RepositoryRecord, RepositoryServiceError> {
        self.create(actor, actor, slug, object_format, correlation_id)
    }

    pub(crate) fn home(
        &self,
        owner: Option<&str>,
    ) -> Result<Vec<HomeRepositoryRecord>, RepositoryServiceError> {
        Ok(Store::open(&self.database)?.home_repositories(owner, HOME_REPOSITORY_LIMIT)?)
    }

    pub(crate) fn create_for_administrator(
        &self,
        owner: &str,
        slug: &str,
        object_format: Kind,
        correlation_id: &str,
    ) -> Result<RepositoryRecord, RepositoryServiceError> {
        self.create("admin-cli", owner, slug, object_format, correlation_id)
    }

    fn create(
        &self,
        actor: &str,
        owner: &str,
        slug: &str,
        object_format: Kind,
        correlation_id: &str,
    ) -> Result<RepositoryRecord, RepositoryServiceError> {
        validate_username(owner)?;
        validate_slug(slug)?;
        let _maintenance = self.maintenance.mutation();
        let object_format_name = object_format_name(object_format)?;
        let created_at = timestamp()?;
        let mut store = Store::open(&self.database)?;
        let target = format!("{owner}/{slug}");
        let result = self.create_inner(
            &mut store,
            actor,
            owner,
            slug,
            object_format,
            object_format_name,
            correlation_id,
            created_at,
        );
        if result.is_err() {
            store.record_audit_event(&NewAuditEvent {
                action: "repository.create",
                actor,
                target: &target,
                outcome: "failure",
                correlation_id,
                created_at,
            })?;
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn create_inner(
        &self,
        store: &mut Store,
        actor: &str,
        owner: &str,
        slug: &str,
        object_format: Kind,
        object_format_name: &str,
        correlation_id: &str,
        created_at: i64,
    ) -> Result<RepositoryRecord, RepositoryServiceError> {
        let id = random_id()?;
        let pending_path = self.root.join(format!(".pending-{id}.git"));
        let final_path = self.root.join(format!("{id}.git"));
        if pending_path.exists() || final_path.exists() {
            return Err(RepositoryServiceError::IdentifierCollision);
        }

        if let Err(error) = GitRepository::create_bare(&pending_path, object_format) {
            remove_created_repository(&pending_path)?;
            return Err(error.into());
        }
        if let Err(source) = fs::rename(&pending_path, &final_path) {
            remove_created_repository(&pending_path)?;
            return Err(RepositoryServiceError::Filesystem {
                path: final_path,
                source,
            });
        }
        let canonical_path = match fs::canonicalize(&final_path) {
            Ok(path) => path,
            Err(source) => {
                remove_created_repository(&final_path)?;
                return Err(RepositoryServiceError::Canonicalize {
                    path: final_path,
                    source,
                });
            }
        };
        if canonical_path.parent() != Some(self.root.as_path()) {
            remove_created_repository(&canonical_path)?;
            return Err(RepositoryServiceError::PathEscape(canonical_path));
        }

        if let Err(error) = store.create_repository(&NewRepository {
            id: &id,
            owner,
            slug,
            object_format: object_format_name,
            created_at,
            origin: RepositoryOrigin::Created,
            initial_references: &[],
            actor,
            correlation_id,
        }) {
            remove_created_repository(&canonical_path)?;
            return Err(error.into());
        }
        Ok(RepositoryRecord {
            id,
            owner: owner.to_owned(),
            slug: slug.to_owned(),
            visibility: "public".to_owned(),
            state: "active".to_owned(),
            object_format: object_format_name.to_owned(),
            created_at,
            archived_at: None,
        })
    }
}

fn random_id() -> Result<String, RepositoryServiceError> {
    let mut bytes = [0_u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| RepositoryServiceError::Random)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn timestamp() -> Result<i64, RepositoryServiceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RepositoryServiceError::Clock)?
        .as_secs()
        .try_into()
        .map_err(|_| RepositoryServiceError::Clock)
}

fn object_format_name(kind: Kind) -> Result<&'static str, RepositoryServiceError> {
    match kind {
        Kind::Sha1 => Ok("sha1"),
        Kind::Sha256 => Ok("sha256"),
        _ => Err(RepositoryServiceError::UnsupportedObjectFormat),
    }
}

fn remove_created_repository(path: &Path) -> Result<(), RepositoryServiceError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(RepositoryServiceError::Filesystem {
            path: path.to_owned(),
            source,
        }),
    }
}

#[derive(Debug, Error)]
pub(crate) enum RepositoryServiceError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    RepositoryName(#[from] RepositoryNameError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Git(#[from] GitRepositoryError),
    #[error("cannot canonicalize path {path}: {source}")]
    Canonicalize {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot access repository path {path}: {source}")]
    Filesystem {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("repository path leaves the repository directory: {0}")]
    PathEscape(PathBuf),
    #[error("random repository ID collision")]
    IdentifierCollision,
    #[error("cannot create a random repository ID")]
    Random,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("repository object format is not supported")]
    UnsupportedObjectFormat,
}
