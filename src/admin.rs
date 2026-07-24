use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gix::hash::Kind;
use rand::TryRng;
use thiserror::Error;

use crate::auth::{AuthError, validate_username};
use crate::domain::repository::{RepositoryNameError, validate_slug};
use crate::git::repository::{GitRepository, GitRepositoryError};
use crate::instance::{InstanceError, InstanceLock, prepare_database, prepare_repository_root};
use crate::repository::{RepositoryService, RepositoryServiceError};
use crate::store::{
    AuditContext, NewRepository, NewRepositoryReference, RepositoryOrigin, RepositoryRecord, Store,
    StoreError,
};

const ADMIN_ACTOR: &str = "admin-cli";

pub(crate) fn maintain(
    instance_dir: &Path,
    retention_days: u32,
) -> Result<crate::store::MaintenanceResult, AdminError> {
    if retention_days == 0 {
        return Err(AdminError::Retention);
    }
    let _lock = InstanceLock::acquire(instance_dir)?;
    let database = prepare_database(instance_dir)?;
    let retention_seconds = i64::from(retention_days)
        .checked_mul(24 * 60 * 60)
        .ok_or(AdminError::Retention)?;
    let cutoff = timestamp()?
        .checked_sub(retention_seconds)
        .ok_or(AdminError::Retention)?;
    Store::open(&database)?.maintain(cutoff).map_err(Into::into)
}

pub(crate) fn create_repository(
    instance_dir: &Path,
    owner: &str,
    slug: &str,
    object_format: Kind,
) -> Result<RepositoryRecord, AdminError> {
    let _lock = InstanceLock::acquire(instance_dir)?;
    let database = prepare_database(instance_dir)?;
    let root = prepare_repository_root(instance_dir)?;
    RepositoryService::new(&database, &root)
        .create_for_administrator(owner, slug, object_format, &random_id()?)
        .map_err(Into::into)
}

pub(crate) fn import_repository(
    instance_dir: &Path,
    owner: &str,
    slug: &str,
    source: &Path,
) -> Result<RepositoryRecord, AdminError> {
    validate_names(owner, slug)?;
    let source = fs::canonicalize(source).map_err(|source_error| AdminError::Canonicalize {
        path: source.to_owned(),
        source: source_error,
    })?;
    administer_repository(
        instance_dir,
        owner,
        slug,
        RepositoryOrigin::Imported,
        |path| {
            if source.starts_with(path.parent().expect("a managed repository has a parent")) {
                return Err(AdminError::ManagedImport(source));
            }
            GitRepository::copy_bare(&source, path).map_err(Into::into)
        },
    )
}

pub(crate) fn rename_repository(
    instance_dir: &Path,
    owner: &str,
    old_slug: &str,
    new_slug: &str,
) -> Result<RepositoryRecord, AdminError> {
    validate_names(owner, old_slug)?;
    validate_slug(new_slug)?;
    let _lock = InstanceLock::acquire(instance_dir)?;
    let database = prepare_database(instance_dir)?;
    let mut store = Store::open(&database)?;
    let changed_at = timestamp()?;
    let correlation_id = random_id()?;
    if let Err(error) = store.rename_repository(
        owner,
        old_slug,
        new_slug,
        changed_at,
        ADMIN_ACTOR,
        &correlation_id,
    ) {
        record_failure(
            &store,
            "repository.rename",
            &format!("{owner}/{old_slug}->{new_slug}"),
            &correlation_id,
            changed_at,
        )?;
        return Err(error.into());
    }
    inspect_with_store(instance_dir, &store, owner, new_slug)
}

pub(crate) fn archive_repository(
    instance_dir: &Path,
    owner: &str,
    slug: &str,
) -> Result<RepositoryRecord, AdminError> {
    validate_names(owner, slug)?;
    let _lock = InstanceLock::acquire(instance_dir)?;
    let database = prepare_database(instance_dir)?;
    let mut store = Store::open(&database)?;
    let changed_at = timestamp()?;
    let correlation_id = random_id()?;
    if let Err(error) =
        store.archive_repository(owner, slug, changed_at, ADMIN_ACTOR, &correlation_id)
    {
        record_failure(
            &store,
            "repository.archive",
            &format!("{owner}/{slug}"),
            &correlation_id,
            changed_at,
        )?;
        return Err(error.into());
    }
    inspect_with_store(instance_dir, &store, owner, slug)
}

pub(crate) fn set_repository_visibility(
    instance_dir: &Path,
    owner: &str,
    slug: &str,
    visibility: &str,
) -> Result<RepositoryRecord, AdminError> {
    validate_names(owner, slug)?;
    let _lock = InstanceLock::acquire(instance_dir)?;
    let database = prepare_database(instance_dir)?;
    let mut store = Store::open(&database)?;
    let changed_at = timestamp()?;
    let correlation_id = random_id()?;
    if let Err(error) = store.set_repository_visibility(
        owner,
        slug,
        visibility,
        changed_at,
        ADMIN_ACTOR,
        &correlation_id,
    ) {
        record_failure(
            &store,
            "repository.visibility",
            &format!("{owner}/{slug}:{visibility}"),
            &correlation_id,
            changed_at,
        )?;
        return Err(error.into());
    }
    inspect_with_store(instance_dir, &store, owner, slug)
}

pub(crate) fn set_repository_collaborator(
    instance_dir: &Path,
    owner: &str,
    slug: &str,
    username: &str,
    role: &str,
) -> Result<RepositoryRecord, AdminError> {
    validate_names(owner, slug)?;
    validate_username(username)?;
    let _lock = InstanceLock::acquire(instance_dir)?;
    let database = prepare_database(instance_dir)?;
    let mut store = Store::open(&database)?;
    let changed_at = timestamp()?;
    let correlation_id = random_id()?;
    if let Err(error) = store.set_repository_collaborator(
        owner,
        slug,
        username,
        role,
        &AuditContext {
            actor: ADMIN_ACTOR,
            correlation_id: &correlation_id,
            created_at: changed_at,
        },
    ) {
        record_failure(
            &store,
            "collaborator.set",
            &format!("{owner}/{slug}:{username}:{role}"),
            &correlation_id,
            changed_at,
        )?;
        return Err(error.into());
    }
    inspect_with_store(instance_dir, &store, owner, slug)
}

pub(crate) fn remove_repository_collaborator(
    instance_dir: &Path,
    owner: &str,
    slug: &str,
    username: &str,
) -> Result<RepositoryRecord, AdminError> {
    validate_names(owner, slug)?;
    validate_username(username)?;
    let _lock = InstanceLock::acquire(instance_dir)?;
    let database = prepare_database(instance_dir)?;
    let mut store = Store::open(&database)?;
    let changed_at = timestamp()?;
    let correlation_id = random_id()?;
    if let Err(error) = store.remove_repository_collaborator(
        owner,
        slug,
        username,
        changed_at,
        ADMIN_ACTOR,
        &correlation_id,
    ) {
        record_failure(
            &store,
            "collaborator.remove",
            &format!("{owner}/{slug}:{username}"),
            &correlation_id,
            changed_at,
        )?;
        return Err(error.into());
    }
    inspect_with_store(instance_dir, &store, owner, slug)
}

pub(crate) fn inspect_repository(
    instance_dir: &Path,
    owner: &str,
    slug: &str,
) -> Result<RepositoryRecord, AdminError> {
    validate_names(owner, slug)?;
    let _lock = InstanceLock::acquire(instance_dir)?;
    let database = prepare_database(instance_dir)?;
    let store = Store::open(&database)?;
    inspect_with_store(instance_dir, &store, owner, slug)
}

pub(crate) fn repository_path(
    instance_dir: &Path,
    repository: &RepositoryRecord,
) -> Result<PathBuf, AdminError> {
    let root = prepare_repository_root(instance_dir)?;
    let path = root.join(format!("{}.git", repository.id));
    fs::canonicalize(&path).map_err(|source| AdminError::Canonicalize { path, source })
}

fn administer_repository(
    instance_dir: &Path,
    owner: &str,
    slug: &str,
    origin: RepositoryOrigin,
    prepare: impl FnOnce(&Path) -> Result<Kind, AdminError>,
) -> Result<RepositoryRecord, AdminError> {
    let _lock = InstanceLock::acquire(instance_dir)?;
    let database = prepare_database(instance_dir)?;
    let mut store = Store::open(&database)?;
    let root = prepare_repository_root(instance_dir)?;
    let created_at = timestamp()?;
    let correlation_id = random_id()?;
    let action = match origin {
        RepositoryOrigin::Created => "repository.create",
        RepositoryOrigin::Imported => "repository.import",
    };
    let audit_target = format!("{owner}/{slug}");
    let id = random_id()?;
    let pending_path = root.join(format!(".pending-{id}.git"));
    let final_path = root.join(format!("{id}.git"));
    if pending_path.exists() || final_path.exists() {
        record_failure(&store, action, &audit_target, &correlation_id, created_at)?;
        return Err(AdminError::IdentifierCollision);
    }

    let object_format = match prepare(&pending_path) {
        Ok(object_format) => object_format,
        Err(error) => {
            remove_created_repository(&pending_path)?;
            record_failure(&store, action, &audit_target, &correlation_id, created_at)?;
            return Err(error);
        }
    };
    fs::rename(&pending_path, &final_path).map_err(|source| AdminError::Filesystem {
        path: final_path.clone(),
        source,
    })?;
    let mut cleanup = RepositoryCleanup::new(final_path.clone());
    import_fault("after-rename")?;
    let canonical_path =
        fs::canonicalize(&final_path).map_err(|source| AdminError::Canonicalize {
            path: final_path.clone(),
            source,
        })?;
    cleanup.path = canonical_path.clone();
    import_fault("after-canonicalize")?;
    if canonical_path.parent() != Some(root.as_path()) {
        remove_created_repository(&canonical_path)?;
        return Err(AdminError::PathEscape(canonical_path));
    }

    let object_format = object_format_name(object_format)?;
    import_fault("after-object-format")?;
    let git = GitRepository::open(&canonical_path)?;
    import_fault("after-open")?;
    let default_branch = git
        .default_branch()?
        .unwrap_or_else(|| "refs/heads/main".to_owned());
    let references = git.references()?;
    let initial_references = references
        .into_iter()
        .filter(|reference| {
            reference.name.starts_with(b"refs/heads/") || reference.name.starts_with(b"refs/tags/")
        })
        .map(|reference| NewRepositoryReference {
            name: reference.name,
            target: reference.target.to_string(),
        })
        .collect::<Vec<_>>();
    import_fault("after-references")?;
    if let Err(error) = store.create_repository(&NewRepository {
        id: &id,
        owner,
        slug,
        object_format,
        default_branch: &default_branch,
        created_at,
        origin,
        initial_references: &initial_references,
        actor: ADMIN_ACTOR,
        correlation_id: &correlation_id,
    }) {
        remove_created_repository(&canonical_path)?;
        record_failure(&store, action, &audit_target, &correlation_id, created_at)?;
        return Err(error.into());
    }
    cleanup.disarm();
    store.repository(owner, slug).map_err(Into::into)
}

struct RepositoryCleanup {
    path: PathBuf,
    armed: bool,
}

impl RepositoryCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RepositoryCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(debug_assertions)]
fn import_fault(point: &'static str) -> Result<(), AdminError> {
    if std::env::var("TIT_TEST_IMPORT_FAIL").as_deref() == Ok(point) {
        Err(AdminError::InjectedFailure(point))
    } else {
        Ok(())
    }
}

#[cfg(not(debug_assertions))]
fn import_fault(_: &'static str) -> Result<(), AdminError> {
    Ok(())
}

fn inspect_with_store(
    instance_dir: &Path,
    store: &Store,
    owner: &str,
    slug: &str,
) -> Result<RepositoryRecord, AdminError> {
    let repository = store.repository(owner, slug)?;
    let path = repository_path(instance_dir, &repository)?;
    let git = GitRepository::open(&path)?;
    if object_format_name(git.object_format())? != repository.object_format {
        return Err(AdminError::ObjectFormatMismatch);
    }
    Ok(repository)
}

fn validate_names(owner: &str, slug: &str) -> Result<(), AdminError> {
    validate_username(owner)?;
    validate_slug(slug)?;
    Ok(())
}

fn record_failure(
    store: &Store,
    action: &str,
    target: &str,
    correlation_id: &str,
    created_at: i64,
) -> Result<(), AdminError> {
    store.record_audit_event(&crate::store::NewAuditEvent {
        action,
        actor: ADMIN_ACTOR,
        target,
        outcome: "failure",
        correlation_id,
        created_at,
    })?;
    Ok(())
}

fn random_id() -> Result<String, AdminError> {
    let mut bytes = [0_u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AdminError::Random)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn timestamp() -> Result<i64, AdminError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AdminError::Clock)?
        .as_secs()
        .try_into()
        .map_err(|_| AdminError::Clock)
}

fn object_format_name(kind: Kind) -> Result<&'static str, AdminError> {
    match kind {
        Kind::Sha1 => Ok("sha1"),
        Kind::Sha256 => Ok("sha256"),
        _ => Err(AdminError::UnsupportedObjectFormat),
    }
}

fn remove_created_repository(path: &Path) -> Result<(), AdminError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(AdminError::Filesystem {
            path: path.to_owned(),
            source,
        }),
    }
}

#[derive(Debug, Error)]
pub(crate) enum AdminError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    RepositoryName(#[from] RepositoryNameError),
    #[error(transparent)]
    Instance(#[from] InstanceError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Git(#[from] GitRepositoryError),
    #[error(transparent)]
    RepositoryService(#[from] RepositoryServiceError),
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
    #[error("cannot import a repository from the managed repository directory: {0}")]
    ManagedImport(PathBuf),
    #[error("random repository ID collision")]
    IdentifierCollision,
    #[error("cannot create a random repository ID")]
    Random,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("retention days must be greater than zero")]
    Retention,
    #[error("repository object format does not match the database")]
    ObjectFormatMismatch,
    #[error("repository object format is not supported")]
    UnsupportedObjectFormat,
    #[cfg(debug_assertions)]
    #[error("injected repository import failure after {0}")]
    InjectedFailure(&'static str),
}
