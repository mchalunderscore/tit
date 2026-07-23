use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rand::rng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use thiserror::Error;

use crate::account::AccountService;
use crate::auth::{AuthError, SshPublicKey};
use crate::backup::OnlineBackupService;
use crate::config::{Config, ConfigError};
use crate::control::{ControlError, RunningControlServer};
use crate::git::transport::{GitRepositories, RepositoryPathError};
use crate::http::{ListenerReadiness, PublicWebConfig, RunningWebServer, WebError};
use crate::instance::{InstanceError, InstanceLock, prepare_database, prepare_repository_root};
use crate::maintenance::MaintenanceGate;
use crate::policy::PolicyError;
use crate::pull_request::{PullRequestError, PullRequestService};
use crate::ssh::{AuthorizedSshKeys, RunningSshServer, SshServerError};
use crate::store::{Store, StoreError};

const SHUTDOWN_DRAIN_LIMIT: Duration = Duration::from_secs(10);

pub(crate) async fn run(config: &Config) -> Result<(), ServeError> {
    let _lock = InstanceLock::acquire(&config.instance_dir)?;
    let database = prepare_database(&config.instance_dir)?;
    let repository_root = prepare_repository_root(&config.instance_dir)?;
    let maintenance = MaintenanceGate::default();
    PullRequestService::new_with_gate(&database, &repository_root, maintenance.clone())
        .recover()?;
    let store = Store::open(&database)?;
    let keys = active_ssh_identities(&store)?;
    let git = GitRepositories::new_managed_authorized_with_gate(
        &repository_root,
        &database,
        maintenance.clone(),
    )?;
    drop(store);

    let accounts = AccountService::new(database);
    let backup = OnlineBackupService::new(
        config.instance_dir.clone(),
        config.config_path.clone(),
        maintenance.clone(),
    );
    let control =
        RunningControlServer::start_with_backup(&config.instance_dir, accounts.clone(), backup)?;
    let authorized_keys = AuthorizedSshKeys::for_accounts(keys);
    let readiness = ListenerReadiness::default();

    let (http_clone_base, ssh_clone_base) = clone_bases(config)?;
    let host_key = load_or_create_host_key(&config.instance_dir)?;
    let reload_keys = {
        let authorized_keys = authorized_keys.clone();
        std::sync::Arc::new(move |accounts: &AccountService| {
            let store = Store::open(accounts.database())?;
            let active = active_ssh_identities(&store)?;
            authorized_keys.replace_accounts(active);
            Ok(())
        })
    };
    let web = RunningWebServer::start_public_with_key_reload(
        config.http_listen,
        PublicWebConfig {
            instance_dir: config.instance_dir.clone(),
            http_clone_base,
            ssh_clone_base,
        },
        reload_keys,
        readiness.clone(),
        maintenance,
    )
    .await?;
    let ssh = match RunningSshServer::start_with_dynamic_keys(
        config.ssh_listen,
        authorized_keys,
        git,
        host_key,
    )
    .await
    {
        Ok(ssh) => ssh,
        Err(error) => {
            control.shutdown().await?;
            web.shutdown().await?;
            return Err(error.into());
        }
    };
    readiness.mark_ready();

    let signal = shutdown_signal().await;
    readiness.mark_stopping();
    let (ssh_result, web_result, control_result) = tokio::join!(
        ssh.shutdown_bounded(SHUTDOWN_DRAIN_LIMIT),
        web.shutdown_bounded(SHUTDOWN_DRAIN_LIMIT),
        control.shutdown_bounded(SHUTDOWN_DRAIN_LIMIT)
    );
    let ssh_drained = ssh_result?;
    let web_drained = web_result?;
    let control_drained = control_result?;
    let drained = ssh_drained && web_drained && control_drained;
    if !drained {
        eprintln!("tit: the shutdown drain limit expired; unfinished connections were canceled");
    }
    signal.map_err(ServeError::Signal)
}

fn active_ssh_identities(store: &Store) -> Result<Vec<(String, SshPublicKey)>, StoreError> {
    store
        .active_ssh_identities()?
        .into_iter()
        .map(|identity| {
            let key = SshPublicKey::parse(&identity.canonical_key)
                .map_err(|error| StoreError::Integrity(error.to_string()))?;
            if key.fingerprint() != identity.fingerprint {
                return Err(StoreError::Integrity(format!(
                    "SSH key fingerprint does not match for account {}",
                    identity.username
                )));
            }
            Ok((identity.username, key))
        })
        .collect()
}

const HOST_KEY_FILE: &str = "ssh_host_ed25519_key";
const MAX_HOST_KEY_BYTES: u64 = 64 * 1024;

fn load_or_create_host_key(instance_dir: &Path) -> Result<PrivateKey, ServeError> {
    let path = instance_dir.join(HOST_KEY_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(ServeError::InvalidHostKeyFile(path));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return create_host_key(&path);
        }
        Err(source) => return Err(ServeError::HostKeyIo { path, source }),
    }
    read_host_key(&path)
}

fn create_host_key(path: &Path) -> Result<PrivateKey, ServeError> {
    let key = PrivateKey::random(&mut rng(), Algorithm::Ed25519)?;
    let encoded = key.to_openssh(LineEnding::LF)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| ServeError::HostKeyIo {
            path: path.to_owned(),
            source,
        })?;
    file.write_all(encoded.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| ServeError::HostKeyIo {
            path: path.to_owned(),
            source,
        })?;
    Ok(key)
}

fn read_host_key(path: &Path) -> Result<PrivateKey, ServeError> {
    let file = File::open(path).map_err(|source| ServeError::HostKeyIo {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ServeError::HostKeyIo {
        path: path.to_owned(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_file() {
        return Err(ServeError::InvalidHostKeyFile(path.to_owned()));
    }
    if mode & 0o077 != 0 {
        return Err(ServeError::HostKeyPermissions {
            path: path.to_owned(),
            mode,
        });
    }
    if metadata.len() > MAX_HOST_KEY_BYTES {
        return Err(ServeError::InvalidHostKeyFile(path.to_owned()));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| ServeError::InvalidHostKeyFile(path.to_owned()))?;
    let mut encoded = Vec::with_capacity(capacity);
    file.take(MAX_HOST_KEY_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|source| ServeError::HostKeyIo {
            path: path.to_owned(),
            source,
        })?;
    if encoded.len() as u64 > MAX_HOST_KEY_BYTES {
        return Err(ServeError::InvalidHostKeyFile(path.to_owned()));
    }
    let key = PrivateKey::from_openssh(&encoded)?;
    if key.algorithm() != Algorithm::Ed25519 || key.is_encrypted() {
        return Err(ServeError::InvalidHostKeyFile(path.to_owned()));
    }
    Ok(key)
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

fn clone_bases(config: &Config) -> Result<(String, String), ConfigError> {
    let (http, ssh) = config.clone_urls("owner", "repository")?;
    let suffix = "/owner/repository";
    Ok((
        http.as_str()
            .strip_suffix(suffix)
            .expect("the HTTP clone URL contains the supplied path")
            .to_owned(),
        ssh.as_str()
            .strip_suffix(suffix)
            .expect("the SSH clone URL contains the supplied path")
            .to_owned(),
    ))
}

#[derive(Debug, Error)]
pub(crate) enum ServeError {
    #[error(transparent)]
    Instance(#[from] InstanceError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    PullRequest(#[from] PullRequestError),
    #[error(transparent)]
    Authentication(#[from] AuthError),
    #[error(transparent)]
    Repository(#[from] RepositoryPathError),
    #[error(transparent)]
    Configuration(#[from] ConfigError),
    #[error(transparent)]
    Web(#[from] WebError),
    #[error(transparent)]
    Ssh(#[from] SshServerError),
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error("cannot wait for a shutdown signal: {0}")]
    Signal(std::io::Error),
    #[error("cannot read or write SSH host key {path}: {source}")]
    HostKeyIo {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("SSH host key path is not a valid Ed25519 private-key file: {0}")]
    InvalidHostKeyFile(PathBuf),
    #[error("SSH host key permissions for {path} are {mode:o}, expected 600 or more restrictive")]
    HostKeyPermissions { path: PathBuf, mode: u32 },
    #[error(transparent)]
    HostKey(#[from] ssh_key::Error),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn persists_a_private_host_key_and_rejects_unsafe_replacements() {
        let directory = TempDir::new().expect("create a host-key directory");
        let first = load_or_create_host_key(directory.path()).expect("create a host key");
        let path = directory.path().join(HOST_KEY_FILE);
        assert_eq!(
            fs::metadata(&path)
                .expect("inspect the host key")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let second = load_or_create_host_key(directory.path()).expect("read the host key");
        assert_eq!(first.public_key(), second.public_key());

        let mut permissions = fs::metadata(&path)
            .expect("inspect the host key")
            .permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&path, permissions).expect("make the host key unsafe");
        assert!(matches!(
            load_or_create_host_key(directory.path()),
            Err(ServeError::HostKeyPermissions { mode: 0o644, .. })
        ));

        fs::remove_file(&path).expect("remove the host key");
        symlink(directory.path().join("target"), &path).expect("replace the host key with a link");
        assert!(matches!(
            load_or_create_host_key(directory.path()),
            Err(ServeError::InvalidHostKeyFile(candidate)) if candidate == path
        ));
    }
}
