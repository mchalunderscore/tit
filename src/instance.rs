use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::store::DATABASE_FILE;

const LOCK_FILE: &str = "tit.lock";
const PRIVATE_MODE: u32 = 0o600;

pub(crate) struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    pub(crate) fn acquire(instance_dir: &Path) -> Result<Self, InstanceError> {
        let directory =
            std::fs::symlink_metadata(instance_dir).map_err(|source| InstanceError::Directory {
                path: instance_dir.to_owned(),
                source,
            })?;
        if !directory.file_type().is_dir() {
            return Err(InstanceError::InvalidDirectory(instance_dir.to_owned()));
        }

        let path = instance_dir.join(LOCK_FILE);
        reject_symlink(&path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(PRIVATE_MODE)
            .open(&path)
            .map_err(|source| InstanceError::Open {
                path: path.clone(),
                source,
            })?;
        validate_private_file(&path, &file)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => Err(InstanceError::Locked),
            Err(TryLockError::Error(source)) => Err(InstanceError::Open { path, source }),
        }
    }
}

pub(crate) fn prepare_database(instance_dir: &Path) -> Result<PathBuf, InstanceError> {
    let path = instance_dir.join(DATABASE_FILE);
    reject_symlink(&path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(PRIVATE_MODE)
        .open(&path)
        .map_err(|source| InstanceError::Open {
            path: path.clone(),
            source,
        })?;
    validate_private_file(&path, &file)?;
    Ok(path)
}

fn reject_symlink(path: &Path) -> Result<(), InstanceError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(InstanceError::Symlink(path.to_owned()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(InstanceError::Open {
            path: path.to_owned(),
            source,
        }),
    }
}

fn validate_private_file(path: &Path, file: &File) -> Result<(), InstanceError> {
    let metadata = file.metadata().map_err(|source| InstanceError::Open {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(InstanceError::InvalidFile(path.to_owned()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(InstanceError::Permissions {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum InstanceError {
    #[error("cannot inspect instance directory {path}: {source}")]
    Directory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("instance path is not a directory: {0}")]
    InvalidDirectory(PathBuf),
    #[error("instance file must not be a symbolic link: {0}")]
    Symlink(PathBuf),
    #[error("instance path is not a regular file: {0}")]
    InvalidFile(PathBuf),
    #[error("instance file permissions for {path} are {mode:o}, expected 600 or more restrictive")]
    Permissions { path: PathBuf, mode: u32 },
    #[error("cannot open instance file {path}: {source}")]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("another process owns the instance lock")]
    Locked,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn serializes_instance_owners_and_rejects_unsafe_files() {
        let directory = TempDir::new().expect("create an instance directory");
        let first = InstanceLock::acquire(directory.path()).expect("acquire the instance lock");
        assert!(matches!(
            InstanceLock::acquire(directory.path()),
            Err(InstanceError::Locked)
        ));
        drop(first);
        InstanceLock::acquire(directory.path()).expect("acquire the released instance lock");

        let lock_path = directory.path().join(LOCK_FILE);
        fs::remove_file(&lock_path).expect("remove the lock file");
        symlink(directory.path().join("target"), &lock_path).expect("create a lock-file symlink");
        assert!(matches!(
            InstanceLock::acquire(directory.path()),
            Err(InstanceError::Symlink(path)) if path == lock_path
        ));
    }

    #[test]
    fn creates_a_private_database_and_rejects_replacements() {
        let directory = TempDir::new().expect("create an instance directory");
        let database = prepare_database(directory.path()).expect("prepare the database");
        assert_eq!(
            fs::metadata(&database)
                .expect("inspect the database")
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_MODE
        );
        let mut permissions = fs::metadata(&database)
            .expect("inspect the database")
            .permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&database, permissions).expect("make the database unsafe");
        assert!(matches!(
            prepare_database(directory.path()),
            Err(InstanceError::Permissions { mode: 0o644, .. })
        ));

        fs::remove_file(&database).expect("remove the database");
        symlink(directory.path().join("target"), &database).expect("create a database symlink");
        assert!(matches!(
            prepare_database(directory.path()),
            Err(InstanceError::Symlink(path)) if path == database
        ));
    }
}
