use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};

const MAX_BLOCKING_GIT_JOBS: usize = 4;

#[derive(Clone)]
pub(crate) struct GitRepositories {
    root: PathBuf,
    blocking_jobs: std::sync::Arc<Semaphore>,
}

impl GitRepositories {
    pub(crate) fn new(root: &Path) -> Result<Self, RepositoryPathError> {
        let root = fs::canonicalize(root).map_err(|source| RepositoryPathError::Root {
            path: root.to_owned(),
            source,
        })?;
        Ok(Self {
            root,
            blocking_jobs: std::sync::Arc::new(Semaphore::new(MAX_BLOCKING_GIT_JOBS)),
        })
    }

    pub(crate) fn resolve(
        &self,
        owner: &str,
        repository: &str,
    ) -> Result<PathBuf, RepositoryPathError> {
        if !valid_name(owner, 40) {
            return Err(RepositoryPathError::InvalidName);
        }
        let repository = repository.strip_suffix(".git").unwrap_or(repository);
        if !valid_name(repository, 100) {
            return Err(RepositoryPathError::InvalidName);
        }
        let candidate = self.root.join(owner).join(format!("{repository}.git"));
        let candidate =
            fs::canonicalize(&candidate).map_err(|source| RepositoryPathError::Repository {
                path: candidate,
                source,
            })?;
        if !candidate.starts_with(&self.root) {
            return Err(RepositoryPathError::OutsideRoot);
        }
        Ok(candidate)
    }

    pub(crate) fn resolve_ssh_command(
        &self,
        command: &[u8],
    ) -> Result<PathBuf, RepositoryPathError> {
        let command =
            std::str::from_utf8(command).map_err(|_| RepositoryPathError::InvalidCommand)?;
        let path = command
            .strip_prefix("git-upload-pack '")
            .and_then(|value| value.strip_suffix('\''))
            .ok_or(RepositoryPathError::InvalidCommand)?;
        if path.contains('\'') {
            return Err(RepositoryPathError::InvalidCommand);
        }
        let path = path.strip_prefix('/').unwrap_or(path);
        let mut components = path.split('/');
        let owner = components
            .next()
            .ok_or(RepositoryPathError::InvalidCommand)?;
        let repository = components
            .next()
            .ok_or(RepositoryPathError::InvalidCommand)?;
        if components.next().is_some() {
            return Err(RepositoryPathError::InvalidCommand);
        }
        self.resolve(owner, repository)
    }

    pub(crate) async fn blocking_permit(&self) -> Result<OwnedSemaphorePermit, AcquireError> {
        self.blocking_jobs.clone().acquire_owned().await
    }
}

fn valid_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        && !value.starts_with(['.', '-', '_'])
        && !value.ends_with(['.', '-', '_'])
        && !value.contains("..")
}

#[derive(Debug, Error)]
pub(crate) enum RepositoryPathError {
    #[error("cannot open repository root {path}: {source}")]
    Root {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("repository owner or name is not valid")]
    InvalidName,
    #[error("SSH Git command is not valid")]
    InvalidCommand,
    #[error("cannot open repository {path}: {source}")]
    Repository {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("repository resolves outside the repository root")]
    OutsideRoot,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn resolves_only_strict_repository_paths_and_commands() {
        let directory = TempDir::new().expect("create a repository root");
        let repository = directory.path().join("alice/example.git");
        fs::create_dir_all(&repository).expect("create a repository");
        let repositories =
            GitRepositories::new(directory.path()).expect("open the repository root");

        assert_eq!(
            repositories
                .resolve("alice", "example")
                .expect("resolve a repository"),
            fs::canonicalize(&repository).expect("canonicalize the repository")
        );
        assert_eq!(
            repositories
                .resolve_ssh_command(b"git-upload-pack '/alice/example.git'")
                .expect("resolve an SSH Git command"),
            fs::canonicalize(&repository).expect("canonicalize the repository")
        );
        for command in [
            b"git-upload-pack '../../etc'".as_slice(),
            b"git-upload-pack '/alice/example.git'; uname".as_slice(),
            b"git-receive-pack '/alice/example.git'".as_slice(),
            b"git-upload-pack '/alice/example.git/extra'".as_slice(),
        ] {
            assert!(repositories.resolve_ssh_command(command).is_err());
        }
    }
}
