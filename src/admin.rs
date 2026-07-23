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
use crate::store::{
    NewRepository, NewRepositoryReference, RepositoryOrigin, RepositoryRecord, Store, StoreError,
};

pub(crate) fn create_repository(
    instance_dir: &Path,
    owner: &str,
    slug: &str,
    object_format: Kind,
) -> Result<RepositoryRecord, AdminError> {
    validate_names(owner, slug)?;
    administer_repository(
        instance_dir,
        owner,
        slug,
        RepositoryOrigin::Created,
        |path| {
            GitRepository::create_bare(path, object_format)?;
            Ok(object_format)
        },
    )
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
    store.rename_repository(owner, old_slug, new_slug)?;
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
    store.archive_repository(owner, slug, timestamp()?)?;
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
    store.set_repository_visibility(owner, slug, visibility)?;
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
    store.set_repository_collaborator(owner, slug, username, role, timestamp()?)?;
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
    store.remove_repository_collaborator(owner, slug, username)?;
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
    let id = random_id()?;
    let pending_path = root.join(format!(".pending-{id}.git"));
    let final_path = root.join(format!("{id}.git"));
    if pending_path.exists() || final_path.exists() {
        return Err(AdminError::IdentifierCollision);
    }

    let object_format = match prepare(&pending_path) {
        Ok(object_format) => object_format,
        Err(error) => {
            remove_created_repository(&pending_path)?;
            return Err(error);
        }
    };
    fs::rename(&pending_path, &final_path).map_err(|source| AdminError::Filesystem {
        path: final_path.clone(),
        source,
    })?;
    let canonical_path =
        fs::canonicalize(&final_path).map_err(|source| AdminError::Canonicalize {
            path: final_path.clone(),
            source,
        })?;
    if canonical_path.parent() != Some(root.as_path()) {
        remove_created_repository(&canonical_path)?;
        return Err(AdminError::PathEscape(canonical_path));
    }

    let created_at = timestamp()?;
    let object_format = object_format_name(object_format)?;
    let git = GitRepository::open(&canonical_path)?;
    let initial_references = git
        .references()?
        .into_iter()
        .filter(|reference| {
            reference.name.starts_with(b"refs/heads/") || reference.name.starts_with(b"refs/tags/")
        })
        .map(|reference| NewRepositoryReference {
            name: reference.name,
            target: reference.target.to_string(),
        })
        .collect::<Vec<_>>();
    if let Err(error) = store.create_repository(&NewRepository {
        id: &id,
        owner,
        slug,
        object_format,
        created_at,
        origin,
        initial_references: &initial_references,
    }) {
        remove_created_repository(&canonical_path)?;
        return Err(error.into());
    }
    store.repository(owner, slug).map_err(Into::into)
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
    #[error("repository object format does not match the database")]
    ObjectFormatMismatch,
    #[error("repository object format is not supported")]
    UnsupportedObjectFormat,
}
