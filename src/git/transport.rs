use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};

const MAX_BLOCKING_GIT_JOBS: usize = 4;

#[derive(Clone)]
pub(crate) struct GitRepositories {
    root: PathBuf,
    managed_public: Option<Arc<HashMap<(String, String), String>>>,
    push_database: Option<PathBuf>,
    push_jobs: std::sync::Arc<Semaphore>,
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
            managed_public: None,
            push_database: None,
            push_jobs: std::sync::Arc::new(Semaphore::new(1)),
            blocking_jobs: std::sync::Arc::new(Semaphore::new(MAX_BLOCKING_GIT_JOBS)),
        })
    }

    pub(crate) fn new_with_pushes(
        root: &Path,
        database: &Path,
    ) -> Result<Self, RepositoryPathError> {
        let mut repositories = Self::new(root)?;
        repositories.push_database = Some(database.to_owned());
        Ok(repositories)
    }

    pub(crate) fn new_managed_public(
        root: &Path,
        repositories: impl IntoIterator<Item = (String, String, String)>,
    ) -> Result<Self, RepositoryPathError> {
        let mut service = Self::new(root)?;
        let mut paths = HashMap::new();
        for (owner, repository, id) in repositories {
            if !valid_managed_id(&id)
                || paths
                    .insert((owner.clone(), repository.clone()), id)
                    .is_some()
            {
                return Err(RepositoryPathError::InvalidCatalog);
            }
        }
        service.managed_public = Some(Arc::new(paths));
        Ok(service)
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
        let candidate = match &self.managed_public {
            Some(repositories) => {
                let id = repositories
                    .get(&(owner.to_owned(), repository.to_owned()))
                    .ok_or_else(|| RepositoryPathError::Repository {
                        path: self.root.join(owner).join(repository),
                        source: std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "repository is not public and active",
                        ),
                    })?;
                self.root.join(format!("{id}.git"))
            }
            None => self.root.join(owner).join(format!("{repository}.git")),
        };
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

    pub(crate) fn resolve_ssh_service(
        &self,
        command: &[u8],
    ) -> Result<GitSshService, RepositoryPathError> {
        if command.starts_with(b"git-upload-pack ") {
            return self.resolve_ssh_command(command).map(GitSshService::Upload);
        }
        let command =
            std::str::from_utf8(command).map_err(|_| RepositoryPathError::InvalidCommand)?;
        let path = command
            .strip_prefix("git-receive-pack '")
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
        self.resolve(owner, repository).map(GitSshService::Receive)
    }

    pub(crate) fn push_database(&self) -> Option<&Path> {
        self.push_database.as_deref()
    }

    pub(crate) async fn push_permit(&self) -> Result<OwnedSemaphorePermit, AcquireError> {
        self.push_jobs.clone().acquire_owned().await
    }

    pub(crate) async fn blocking_permit(&self) -> Result<OwnedSemaphorePermit, AcquireError> {
        self.blocking_jobs.clone().acquire_owned().await
    }
}

fn valid_managed_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) enum GitSshService {
    Upload(PathBuf),
    Receive(PathBuf),
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
    #[error("managed repository catalog is not valid")]
    InvalidCatalog,
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
        assert!(matches!(
            repositories
                .resolve_ssh_service(b"git-receive-pack '/alice/example.git'")
                .expect("resolve receive-pack"),
            GitSshService::Receive(path) if path == fs::canonicalize(&repository).expect("canonicalize the repository")
        ));
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

    #[test]
    fn resolves_managed_public_repositories_by_immutable_id() {
        let directory = TempDir::new().expect("create a managed repository root");
        let id = "11111111111111111111111111111111";
        let repository = directory.path().join(format!("{id}.git"));
        fs::create_dir(&repository).expect("create a managed repository");
        let repositories = GitRepositories::new_managed_public(
            directory.path(),
            [("alice".to_owned(), "example".to_owned(), id.to_owned())],
        )
        .expect("open the managed repository root");

        assert_eq!(
            repositories
                .resolve_ssh_command(b"git-upload-pack '/alice/example.git'")
                .expect("resolve a managed repository"),
            fs::canonicalize(&repository).expect("canonicalize the managed repository")
        );
        assert!(repositories.resolve("alice", "missing").is_err());
        assert!(matches!(
            GitRepositories::new_managed_public(
                directory.path(),
                [("alice".to_owned(), "bad".to_owned(), "not-an-id".to_owned())]
            ),
            Err(RepositoryPathError::InvalidCatalog)
        ));
    }
}
