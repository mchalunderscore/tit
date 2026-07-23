use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};

use crate::policy::{RepositoryOperation, RepositoryPolicy};

const MAX_BLOCKING_GIT_JOBS: usize = 4;

#[derive(Clone)]
pub(crate) struct GitRepositories {
    root: PathBuf,
    managed_public: Option<Arc<HashMap<(String, String), String>>>,
    policy: Option<RepositoryPolicy>,
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
            policy: None,
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

    pub(crate) fn new_managed_authorized(
        root: &Path,
        database: &Path,
    ) -> Result<Self, RepositoryPathError> {
        let mut service = Self::new(root)?;
        service.push_database = Some(database.to_owned());
        service.policy = Some(RepositoryPolicy::new(database));
        Ok(service)
    }

    pub(crate) fn resolve(
        &self,
        owner: &str,
        repository: &str,
    ) -> Result<PathBuf, RepositoryPathError> {
        self.resolve_for(None, owner, repository, RepositoryOperation::Read)
    }

    fn resolve_for(
        &self,
        actor: Option<&str>,
        owner: &str,
        repository: &str,
        operation: RepositoryOperation,
    ) -> Result<PathBuf, RepositoryPathError> {
        if !valid_name(owner, 40) {
            return Err(RepositoryPathError::InvalidName);
        }
        let repository = repository.strip_suffix(".git").unwrap_or(repository);
        if !valid_name(repository, 100) {
            return Err(RepositoryPathError::InvalidName);
        }
        let candidate = if let Some(policy) = &self.policy {
            let record = policy
                .authorize(actor, owner, repository, operation)
                .map_err(|_| RepositoryPathError::Unauthorized)?;
            self.root.join(format!("{}.git", record.id))
        } else {
            match &self.managed_public {
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
            }
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
        self.resolve_ssh_service_for(None, command)
    }

    pub(crate) fn resolve_ssh_service_for(
        &self,
        actor: Option<&str>,
        command: &[u8],
    ) -> Result<GitSshService, RepositoryPathError> {
        if command.starts_with(b"git-upload-pack ") {
            let (owner, repository) = parse_ssh_repository(command, "git-upload-pack '")?;
            let path = self.resolve_for(actor, &owner, &repository, RepositoryOperation::Read)?;
            return Ok(GitSshService::Upload {
                path,
                owner,
                repository,
            });
        }
        let (owner, repository) = parse_ssh_repository(command, "git-receive-pack '")?;
        let path = self.resolve_for(actor, &owner, &repository, RepositoryOperation::Write)?;
        Ok(GitSshService::Receive {
            path,
            owner,
            repository,
        })
    }

    pub(crate) fn authorize(
        &self,
        actor: &str,
        owner: &str,
        repository: &str,
        operation: RepositoryOperation,
    ) -> bool {
        self.policy.as_ref().is_none_or(|policy| {
            policy
                .authorize(Some(actor), owner, repository, operation)
                .is_ok()
        })
    }

    pub(crate) fn uses_policy(&self) -> bool {
        self.policy.is_some()
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
    Upload {
        path: PathBuf,
        owner: String,
        repository: String,
    },
    Receive {
        path: PathBuf,
        owner: String,
        repository: String,
    },
}

fn parse_ssh_repository(
    command: &[u8],
    prefix: &str,
) -> Result<(String, String), RepositoryPathError> {
    let command = std::str::from_utf8(command).map_err(|_| RepositoryPathError::InvalidCommand)?;
    let path = command
        .strip_prefix(prefix)
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
    let repository = repository.strip_suffix(".git").unwrap_or(repository);
    Ok((owner.to_owned(), repository.to_owned()))
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
    #[error("repository access is not authorized")]
    Unauthorized,
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
            GitSshService::Receive { path, .. } if path == fs::canonicalize(&repository).expect("canonicalize the repository")
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
