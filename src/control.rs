use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::account::{AccountError, AccountService};

pub(crate) const CONTROL_SOCKET_FILE: &str = "control.sock";
const REQUEST: &[u8] = b"invite-code\n";
const MAX_RESPONSE_BYTES: usize = 256;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct RunningControlServer {
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), ControlError>>,
}

impl RunningControlServer {
    pub(crate) fn start(
        instance_dir: &Path,
        accounts: AccountService,
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
            loop {
                tokio::select! {
                    _ = &mut receiver => return Ok(()),
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.map_err(ControlError::Accept)?;
                        let service = accounts.clone();
                        tokio::spawn(async move {
                            let _ = handle(stream, service).await;
                        });
                    }
                }
            }
        });
        Ok(Self { shutdown, task })
    }

    pub(crate) async fn shutdown(self) -> Result<(), ControlError> {
        let _ = self.shutdown.send(());
        self.task.await.map_err(|_| ControlError::Join)??;
        Ok(())
    }
}

pub(crate) async fn request_invitation(instance_dir: &Path) -> Result<String, ControlError> {
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
        stream.write_all(REQUEST).await?;
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
            .strip_prefix("ok ")
            .and_then(|value| value.strip_suffix('\n'))
            .map(str::to_owned)
            .ok_or(ControlError::InvalidResponse)
    };
    tokio::time::timeout(IO_TIMEOUT, operation)
        .await
        .map_err(|_| ControlError::Timeout)?
}

async fn handle(mut stream: UnixStream, accounts: AccountService) -> Result<(), ControlError> {
    let mut request = Vec::new();
    tokio::time::timeout(
        IO_TIMEOUT,
        (&mut stream)
            .take((REQUEST.len() + 1) as u64)
            .read_to_end(&mut request),
    )
    .await
    .map_err(|_| ControlError::Timeout)??;
    if request != REQUEST {
        stream.write_all(b"error invalid-request\n").await?;
        return Ok(());
    }
    let invitation = tokio::task::spawn_blocking(move || accounts.issue_invitation())
        .await
        .map_err(|_| ControlError::Join)??;
    stream
        .write_all(format!("ok {invitation}\n").as_bytes())
        .await?;
    stream.shutdown().await?;
    Ok(())
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
    #[error("control task failed")]
    Join,
    #[error(transparent)]
    Account(#[from] AccountError),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

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
}
