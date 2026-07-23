use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

use crate::account::{AccountError, AccountService};
use crate::backup::OnlineBackupService;

pub(crate) const CONTROL_SOCKET_FILE: &str = "control.sock";
const REQUEST: &[u8] = b"invite-code\n";
const BACKUP_REQUEST_PREFIX: &[u8] = b"backup ";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 256;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const BACKUP_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub(crate) struct RunningControlServer {
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), ControlError>>,
}

impl RunningControlServer {
    #[allow(
        dead_code,
        reason = "the production server uses the backup-enabled constructor"
    )]
    pub(crate) fn start(
        instance_dir: &Path,
        accounts: AccountService,
    ) -> Result<Self, ControlError> {
        Self::start_inner(instance_dir, accounts, None)
    }

    pub(crate) fn start_with_backup(
        instance_dir: &Path,
        accounts: AccountService,
        backup: OnlineBackupService,
    ) -> Result<Self, ControlError> {
        Self::start_inner(instance_dir, accounts, Some(backup))
    }

    fn start_inner(
        instance_dir: &Path,
        accounts: AccountService,
        backup: Option<OnlineBackupService>,
    ) -> Result<Self, ControlError> {
        let path = instance_dir.join(CONTROL_SOCKET_FILE);
        refuse_existing_path(&path)?;
        let listener = UnixListener::bind(&path).map_err(|source| ControlError::Io {
            path: path.clone(),
            source,
        })?;
        let created = fs::symlink_metadata(&path).map_err(|source| ControlError::Io {
            path: path.clone(),
            source,
        })?;
        if !created.file_type().is_socket() {
            return Err(ControlError::UnsafePath(path));
        }
        let cleanup = SocketCleanup {
            path: path.clone(),
            identity: SocketIdentity {
                device: created.dev(),
                inode: created.ino(),
            },
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            ControlError::Io {
                path: path.clone(),
                source,
            }
        })?;
        let metadata = fs::symlink_metadata(&path).map_err(|source| ControlError::Io {
            path: path.clone(),
            source,
        })?;
        if !metadata.file_type().is_socket()
            || metadata.dev() != cleanup.identity.device
            || metadata.ino() != cleanup.identity.inode
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(ControlError::UnsafePath(path));
        }
        let (shutdown, mut receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _cleanup = cleanup;
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut receiver => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.map_err(ControlError::Accept)?;
                        let service = accounts.clone();
                        let backup = backup.clone();
                        connections.spawn(async move {
                            let _ = handle(stream, service, backup).await;
                        });
                    },
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            while connections.join_next().await.is_some() {}
            Ok(())
        });
        Ok(Self { shutdown, task })
    }

    pub(crate) async fn shutdown(self) -> Result<(), ControlError> {
        let _ = self.shutdown.send(());
        self.task.await.map_err(|_| ControlError::Join)??;
        Ok(())
    }

    pub(crate) async fn shutdown_bounded(mut self, limit: Duration) -> Result<bool, ControlError> {
        let _ = self.shutdown.send(());
        match tokio::time::timeout(limit, &mut self.task).await {
            Ok(result) => {
                result.map_err(|_| ControlError::Join)??;
                Ok(true)
            }
            Err(_) => {
                self.task.abort();
                let _ = self.task.await;
                Ok(false)
            }
        }
    }
}

pub(crate) async fn request_invitation(instance_dir: &Path) -> Result<String, ControlError> {
    let response = request(instance_dir, REQUEST, IO_TIMEOUT).await?;
    response
        .strip_prefix("ok ")
        .map(str::to_owned)
        .ok_or(ControlError::InvalidResponse)
}

pub(crate) async fn request_backup(instance_dir: &Path, output: &Path) -> Result<(), ControlError> {
    let mut request_bytes = BACKUP_REQUEST_PREFIX.to_vec();
    request_bytes.extend_from_slice(encode_hex(output.as_os_str().as_bytes()).as_bytes());
    request_bytes.push(b'\n');
    let response = request(instance_dir, &request_bytes, BACKUP_TIMEOUT).await?;
    if response == "ok" {
        Ok(())
    } else if let Some(message) = response.strip_prefix("error ") {
        Err(ControlError::Remote(message.to_owned()))
    } else {
        Err(ControlError::InvalidResponse)
    }
}

async fn request(
    instance_dir: &Path,
    request: &[u8],
    timeout: Duration,
) -> Result<String, ControlError> {
    let path = instance_dir.join(CONTROL_SOCKET_FILE);
    let metadata = fs::symlink_metadata(&path).map_err(|source| ControlError::Io {
        path: path.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ControlError::UnsafePath(path));
    }
    let operation = async {
        let mut stream = UnixStream::connect(&path).await?;
        stream.write_all(request).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .await?;
        if response.len() > MAX_RESPONSE_BYTES {
            return Err(ControlError::InvalidResponse);
        }
        let response = String::from_utf8(response).map_err(|_| ControlError::InvalidResponse)?;
        response
            .strip_suffix('\n')
            .map(str::to_owned)
            .ok_or(ControlError::InvalidResponse)
    };
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| ControlError::Timeout)?
}

async fn handle(
    mut stream: UnixStream,
    accounts: AccountService,
    backup: Option<OnlineBackupService>,
) -> Result<(), ControlError> {
    let mut request = Vec::new();
    tokio::time::timeout(
        IO_TIMEOUT,
        (&mut stream)
            .take((MAX_REQUEST_BYTES + 1) as u64)
            .read_to_end(&mut request),
    )
    .await
    .map_err(|_| ControlError::Timeout)??;
    if request.len() > MAX_REQUEST_BYTES {
        stream.write_all(b"error invalid-request\n").await?;
        return Ok(());
    }
    if request == REQUEST {
        let invitation = tokio::task::spawn_blocking(move || accounts.issue_invitation())
            .await
            .map_err(|_| ControlError::Join)??;
        stream
            .write_all(format!("ok {invitation}\n").as_bytes())
            .await?;
    } else if let Some(encoded) = request
        .strip_prefix(BACKUP_REQUEST_PREFIX)
        .and_then(|value| value.strip_suffix(b"\n"))
    {
        let Some(backup) = backup else {
            stream.write_all(b"error backup-unavailable\n").await?;
            return Ok(());
        };
        let output = match decode_hex(encoded) {
            Some(path) => PathBuf::from(OsString::from_vec(path)),
            None => {
                stream.write_all(b"error invalid-request\n").await?;
                return Ok(());
            }
        };
        match backup.create(output).await {
            Ok(()) => stream.write_all(b"ok\n").await?,
            Err(_) => stream.write_all(b"error backup-failed\n").await?,
        }
    } else {
        stream.write_all(b"error invalid-request\n").await?;
    }
    stream.shutdown().await?;
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
}

fn decode_hex(encoded: &[u8]) -> Option<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        return None;
    }
    encoded
        .chunks_exact(2)
        .map(|pair| Some((decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?))
        .collect()
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn refuse_existing_path(path: &Path) -> Result<(), ControlError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() => {
            Err(ControlError::UnsafePath(path.to_owned()))
        }
        Ok(_) => Err(ControlError::SocketExists(path.to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ControlError::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

struct SocketIdentity {
    device: u64,
    inode: u64,
}

struct SocketCleanup {
    path: PathBuf,
    identity: SocketIdentity,
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.identity.device
            && metadata.ino() == self.identity.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ControlError {
    #[error("control socket path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("control socket already exists: {0}")]
    SocketExists(PathBuf),
    #[error("control socket error for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("control socket accept failed: {0}")]
    Accept(std::io::Error),
    #[error("control socket I/O failed: {0}")]
    ProtocolIo(#[from] std::io::Error),
    #[error("control request timed out")]
    Timeout,
    #[error("control response is invalid")]
    InvalidResponse,
    #[error("control request failed: {0}")]
    Remote(String),
    #[error("control task failed")]
    Join,
    #[error(transparent)]
    Account(#[from] AccountError),
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, symlink};

    use tempfile::TempDir;

    use crate::maintenance::MaintenanceGate;
    use crate::store::Store;

    use super::*;

    #[tokio::test]
    async fn creates_a_private_socket_and_removes_it_after_shutdown() {
        let directory = TempDir::new().expect("create a control directory");
        let database = directory.path().join("tit.sqlite3");
        Store::open(&database).expect("create the database");
        let server =
            RunningControlServer::start(directory.path(), AccountService::new(database.clone()))
                .expect("start the control server");
        let path = directory.path().join(CONTROL_SOCKET_FILE);
        assert_eq!(
            fs::symlink_metadata(&path)
                .expect("inspect the socket")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let invitation = request_invitation(directory.path())
            .await
            .expect("request an invitation");
        assert!(invitation.starts_with("tit-invite-v1:"));
        server.shutdown().await.expect("stop the control server");
        assert!(!path.exists());

        let _socket = std::os::unix::net::UnixListener::bind(&path)
            .expect("create an existing control socket");
        assert!(matches!(
            RunningControlServer::start(directory.path(), AccountService::new(database)),
            Err(ControlError::SocketExists(candidate)) if candidate == path
        ));
    }

    #[test]
    fn refuses_file_and_symlink_replacements() {
        let directory = TempDir::new().expect("create a control directory");
        let path = directory.path().join(CONTROL_SOCKET_FILE);
        fs::write(&path, b"replacement").expect("write a replacement");
        assert!(matches!(
            RunningControlServer::start(
                directory.path(),
                AccountService::new(directory.path().join("tit.sqlite3"))
            ),
            Err(ControlError::UnsafePath(candidate)) if candidate == path
        ));
        fs::remove_file(&path).expect("remove the replacement");
        symlink(directory.path().join("target"), &path).expect("create a replacement link");
        assert!(matches!(
            RunningControlServer::start(
                directory.path(),
                AccountService::new(directory.path().join("tit.sqlite3"))
            ),
            Err(ControlError::UnsafePath(candidate)) if candidate == path
        ));
    }

    #[tokio::test]
    async fn online_backup_waits_for_a_git_mutation() {
        let directory = TempDir::new().expect("create an instance directory");
        let config = directory.path().join("config.toml");
        let mut config_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config)
            .expect("create the configuration");
        config_file
            .write_all(b"version = 1\npublic_url = \"http://localhost:3000/\"\n")
            .expect("write the configuration");
        let database = directory.path().join(crate::store::DATABASE_FILE);
        Store::open(&database).expect("create the database");
        fs::create_dir(directory.path().join(crate::instance::REPOSITORY_DIRECTORY))
            .expect("create the repository directory");

        let gate = MaintenanceGate::default();
        let mutation = gate.mutation_async().await;
        let backup_directory = TempDir::new().expect("create a backup directory");
        let output = backup_directory.path().join("instance.tar");
        let service = OnlineBackupService::new(directory.path().to_owned(), config, gate.clone());
        let server = RunningControlServer::start_with_backup(
            directory.path(),
            AccountService::new(database),
            service,
        )
        .expect("start the control server");

        let request = tokio::spawn({
            let instance = directory.path().to_owned();
            let output = output.clone();
            async move { request_backup(&instance, &output).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!output.exists());
        drop(mutation);
        request
            .await
            .expect("join the backup request")
            .expect("create the online backup");
        assert_eq!(
            fs::metadata(&output)
                .expect("inspect the backup")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        server.shutdown().await.expect("stop the control server");
    }
}
