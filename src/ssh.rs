use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rand::rng;
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Preferred, Pty};
use ssh_key::{Algorithm, EcdsaCurve, PrivateKey, PublicKey};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::auth::SshPublicKey;
use crate::git::packetline::{MAX_REQUEST_BYTES, Packet, decode, encode_data, first_flush_end};
use crate::git::receive_pack::{ReceivePack, ReceivePackError};
use crate::git::transport::{GitRepositories, GitSshService};
use crate::git::upload_pack::{ProtocolVersion, UploadPack, UploadPackError};
use crate::policy::RepositoryOperation;
use crate::repository::{RepositoryService, RepositoryServiceError};

const VERSION_COMMAND: &[u8] = b"tit --version";
const GIT_PROTOCOL_VARIABLE: &str = "GIT_PROTOCOL";
const MAX_RECEIVE_PACK_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REPOSITORY_COMMAND_BYTES: usize = 512;
const REPOSITORY_CREATE_USAGE: &str =
    "repo create NAME [--object-format sha1|sha256] [--output human|json]";

pub(crate) struct RunningSshServer {
    address: SocketAddr,
    handle: russh::server::RunningServerHandle,
    task: JoinHandle<std::io::Result<()>>,
    audit: Arc<RequestAudit>,
}

#[derive(Clone)]
pub(crate) struct AuthorizedSshKeys {
    keys: Arc<RwLock<HashMap<PublicKey, SshIdentity>>>,
}

#[derive(Clone, PartialEq, Eq)]
struct SshIdentity {
    username: String,
    fingerprint: String,
}

impl AuthorizedSshKeys {
    pub(crate) fn new(keys: &[SshPublicKey]) -> Self {
        Self {
            keys: Arc::new(RwLock::new(key_map(keys))),
        }
    }

    pub(crate) fn for_accounts(keys: Vec<(String, SshPublicKey)>) -> Self {
        Self {
            keys: Arc::new(RwLock::new(account_key_map(keys))),
        }
    }

    pub(crate) fn replace_accounts(&self, keys: Vec<(String, SshPublicKey)>) {
        if let Ok(mut current) = self.keys.write() {
            *current = account_key_map(keys);
        }
    }

    fn identity(&self, key: &PublicKey) -> Option<SshIdentity> {
        self.keys.read().ok()?.get(key).cloned()
    }

    fn contains(&self, key: &PublicKey) -> bool {
        self.keys.read().is_ok_and(|keys| keys.contains_key(key))
    }
}

fn key_map(keys: &[SshPublicKey]) -> HashMap<PublicKey, SshIdentity> {
    keys.iter()
        .map(|key| {
            let fingerprint = key.fingerprint().to_owned();
            (
                key.public_key().clone(),
                SshIdentity {
                    username: fingerprint.clone(),
                    fingerprint,
                },
            )
        })
        .collect()
}

fn account_key_map(keys: Vec<(String, SshPublicKey)>) -> HashMap<PublicKey, SshIdentity> {
    keys.into_iter()
        .map(|(username, key)| {
            (
                key.public_key().clone(),
                SshIdentity {
                    username,
                    fingerprint: key.fingerprint().to_owned(),
                },
            )
        })
        .collect()
}

impl RunningSshServer {
    pub(crate) async fn start(
        address: SocketAddr,
        authorized_keys: &[SshPublicKey],
    ) -> Result<Self, SshServerError> {
        let host_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519)?;
        Self::start_inner(address, authorized_keys, &[], None, host_key).await
    }

    pub(crate) async fn start_with_git(
        address: SocketAddr,
        authorized_keys: &[SshPublicKey],
        repositories: GitRepositories,
    ) -> Result<Self, SshServerError> {
        let host_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519)?;
        Self::start_inner(address, authorized_keys, &[], Some(repositories), host_key).await
    }

    pub(crate) async fn start_with_git_and_host_key(
        address: SocketAddr,
        authorized_keys: &[SshPublicKey],
        repositories: GitRepositories,
        host_key: PrivateKey,
    ) -> Result<Self, SshServerError> {
        Self::start_inner(address, authorized_keys, &[], Some(repositories), host_key).await
    }

    pub(crate) async fn start_with_dynamic_keys(
        address: SocketAddr,
        authorized_keys: AuthorizedSshKeys,
        repositories: GitRepositories,
        host_key: PrivateKey,
    ) -> Result<Self, SshServerError> {
        recover_pushes(&repositories).await?;
        Self::start_inner_with_keys(address, authorized_keys, &[], Some(repositories), host_key)
            .await
    }

    pub(crate) async fn start_with_git_writes(
        address: SocketAddr,
        authorized_keys: &[SshPublicKey],
        writable_keys: &[SshPublicKey],
        repositories: GitRepositories,
    ) -> Result<Self, SshServerError> {
        recover_pushes(&repositories).await?;
        let host_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519)?;
        Self::start_inner(
            address,
            authorized_keys,
            writable_keys,
            Some(repositories),
            host_key,
        )
        .await
    }

    async fn start_inner(
        address: SocketAddr,
        authorized_keys: &[SshPublicKey],
        writable_keys: &[SshPublicKey],
        repositories: Option<GitRepositories>,
        host_key: PrivateKey,
    ) -> Result<Self, SshServerError> {
        Self::start_inner_with_keys(
            address,
            AuthorizedSshKeys::new(authorized_keys),
            writable_keys,
            repositories,
            host_key,
        )
        .await
    }

    async fn start_inner_with_keys(
        address: SocketAddr,
        authorized_keys: AuthorizedSshKeys,
        writable_keys: &[SshPublicKey],
        repositories: Option<GitRepositories>,
        host_key: PrivateKey,
    ) -> Result<Self, SshServerError> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let mut methods = MethodSet::empty();
        methods.push(MethodKind::PublicKey);
        let config = Arc::new(russh::server::Config {
            methods,
            auth_rejection_time: Duration::from_millis(250),
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            preferred: Preferred {
                key: Cow::Owned(vec![
                    Algorithm::Ed25519,
                    Algorithm::Ecdsa {
                        curve: EcdsaCurve::NistP256,
                    },
                ]),
                ..Preferred::default()
            },
            max_auth_attempts: 3,
            inactivity_timeout: Some(Duration::from_secs(30)),
            nodelay: true,
            ..Default::default()
        });
        let writable_keys = Arc::new(
            writable_keys
                .iter()
                .map(|key| key.public_key().clone())
                .collect(),
        );
        let audit = Arc::new(RequestAudit::default());
        let server = SshServer {
            authorized_keys,
            writable_keys,
            audit: Arc::clone(&audit),
            repositories: repositories.map(Arc::new),
        };
        let (handle_sender, handle_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut server = server;
            let running = server.run_on_socket(config, &listener);
            let _ = handle_sender.send(running.handle());
            running.await
        });
        let handle = handle_receiver.await.map_err(|_| SshServerError::Startup)?;
        Ok(Self {
            address,
            handle,
            task,
            audit,
        })
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn audit(&self) -> RequestAuditSnapshot {
        self.audit.snapshot()
    }

    pub(crate) async fn shutdown(self) -> Result<(), SshServerError> {
        self.handle.shutdown("tit test shutdown".to_owned());
        self.task.await.map_err(|_| SshServerError::Join)??;
        Ok(())
    }
}

async fn recover_pushes(repositories: &GitRepositories) -> Result<(), SshServerError> {
    let database = repositories
        .push_database()
        .ok_or_else(|| SshServerError::Recovery("push storage is not configured".to_owned()))?
        .to_owned();
    tokio::task::spawn_blocking(move || {
        crate::git::receive_pack::recover_incomplete_pushes(&database)
    })
    .await
    .map_err(|_| SshServerError::Join)?
    .map_err(|error| SshServerError::Recovery(error.to_string()))
}

#[derive(Debug, Error)]
pub(crate) enum SshServerError {
    #[error("SSH listener error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SSH key error: {0}")]
    Key(#[from] ssh_key::Error),
    #[error("SSH server did not start")]
    Startup,
    #[error("SSH server task failed")]
    Join,
    #[error("cannot recover Git writes: {0}")]
    Recovery(String),
}

#[derive(Clone)]
struct SshServer {
    authorized_keys: AuthorizedSshKeys,
    writable_keys: Arc<HashSet<PublicKey>>,
    audit: Arc<RequestAudit>,
    repositories: Option<Arc<GitRepositories>>,
}

impl Server for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, _peer_address: Option<SocketAddr>) -> Self::Handler {
        SshSession {
            authorized_keys: self.authorized_keys.clone(),
            writable_keys: Arc::clone(&self.writable_keys),
            audit: Arc::clone(&self.audit),
            repositories: self.repositories.clone(),
            protocol: ProtocolVersion::V0,
            git_channels: HashMap::new(),
            authenticated_identity: None,
            authenticated_key: None,
            authenticated_writer: false,
        }
    }
}

struct SshSession {
    authorized_keys: AuthorizedSshKeys,
    writable_keys: Arc<HashSet<PublicKey>>,
    audit: Arc<RequestAudit>,
    repositories: Option<Arc<GitRepositories>>,
    protocol: ProtocolVersion,
    git_channels: HashMap<ChannelId, GitChannel>,
    authenticated_identity: Option<SshIdentity>,
    authenticated_key: Option<PublicKey>,
    authenticated_writer: bool,
}

enum GitChannel {
    Upload(Box<UploadChannel>),
    Receive(Box<ReceiveChannel>),
}

struct UploadChannel {
    service: UploadPack,
    request: Vec<u8>,
}

struct ReceiveChannel {
    service: ReceivePack,
    owner: String,
    repository: String,
    identity: SshIdentity,
    public_key: PublicKey,
    authorized_keys: AuthorizedSshKeys,
    commands: Vec<u8>,
    commands_complete: bool,
    pack: tokio::fs::File,
    pack_bytes: u64,
}

impl Handler for SshSession {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(self.authorize(public_key))
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if let Some(identity) = self.authorized_keys.identity(public_key) {
            self.authenticated_identity = Some(identity);
            self.authenticated_key = Some(public_key.clone());
            self.authenticated_writer = self.writable_keys.contains(public_key);
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        _reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.audit.rejected_forward.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.audit.rejected_forward.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        _reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.audit.rejected_forward.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.audit.rejected_pty.fetch_add(1, Ordering::Relaxed);
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.audit.rejected_forward.fetch_add(1, Ordering::Relaxed);
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if variable_name == GIT_PROTOCOL_VARIABLE && valid_git_protocol(variable_value) {
            self.protocol = match variable_value {
                "version=0" => ProtocolVersion::V0,
                "version=1" => ProtocolVersion::V1,
                "version=2" => ProtocolVersion::V2,
                _ => unreachable!("the Git protocol value was validated"),
            };
            self.audit.accepted_env.fetch_add(1, Ordering::Relaxed);
            session.channel_success(channel)?;
        } else {
            self.audit.rejected_env.fetch_add(1, Ordering::Relaxed);
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.audit.rejected_shell.fetch_add(1, Ordering::Relaxed);
        session.channel_failure(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if command == VERSION_COMMAND {
            self.audit.accepted_exec.fetch_add(1, Ordering::Relaxed);
            session.channel_success(channel)?;
            session.data(
                channel,
                format!("tit {}\n", env!("CARGO_PKG_VERSION")).into_bytes(),
            )?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else if is_repository_command(command) {
            self.audit.accepted_exec.fetch_add(1, Ordering::Relaxed);
            session.channel_success(channel)?;
            let machine_requested = requests_json(command);
            let result = match parse_repository_command(command) {
                Ok(command) => match self.active_identity() {
                    Some(identity) => {
                        run_repository_command(
                            self.repositories.clone(),
                            identity.username.clone(),
                            command,
                        )
                        .await
                    }
                    None => Err(RepositoryCommandError::Unavailable),
                },
                Err(()) => Err(RepositoryCommandError::Usage),
            };
            send_repository_command_result(channel, result, machine_requested, session)?;
        } else {
            let service = self.open_git_service(command).await;
            if let Some(service) = service {
                self.audit.accepted_exec.fetch_add(1, Ordering::Relaxed);
                session.channel_success(channel)?;
                match service {
                    InitialGitService::Upload {
                        service,
                        advertisement,
                    } => {
                        session.data(channel, advertisement)?;
                        self.git_channels.insert(
                            channel,
                            GitChannel::Upload(Box::new(UploadChannel {
                                service: *service,
                                request: Vec::new(),
                            })),
                        );
                    }
                    InitialGitService::Receive(receive) => {
                        let InitialReceiveService {
                            service,
                            advertisement,
                            owner,
                            repository,
                            identity,
                            public_key,
                        } = *receive;
                        session.data(channel, advertisement)?;
                        let pack = tokio::fs::File::create(service.incoming_pack()).await;
                        match pack {
                            Ok(pack) => {
                                self.git_channels.insert(
                                    channel,
                                    GitChannel::Receive(Box::new(ReceiveChannel {
                                        service: *service,
                                        owner,
                                        repository,
                                        identity,
                                        public_key,
                                        authorized_keys: self.authorized_keys.clone(),
                                        commands: Vec::new(),
                                        commands_complete: false,
                                        pack,
                                        pack_bytes: 0,
                                    })),
                                );
                            }
                            Err(_) => fail_git_channel(channel, session)?,
                        }
                    }
                }
            } else {
                self.audit.rejected_exec.fetch_add(1, Ordering::Relaxed);
                session.channel_failure(channel)?;
                session.close(channel)?;
            }
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(git) = self.git_channels.remove(&channel) else {
            return Ok(());
        };
        let mut git = match git {
            GitChannel::Upload(git) => git,
            GitChannel::Receive(mut git) => {
                if receive_data(&mut git, data).await.is_err() {
                    fail_git_channel(channel, session)?;
                } else if git.commands_complete
                    && matches!(git.service.expects_pack(&git.commands), Ok(false))
                {
                    send_receive_result(
                        channel,
                        finish_receive(self.repositories.clone(), git).await,
                        session,
                    )?;
                } else {
                    self.git_channels.insert(channel, GitChannel::Receive(git));
                }
                return Ok(());
            }
        };
        if git.request.len().saturating_add(data.len()) > MAX_REQUEST_BYTES {
            fail_git_channel(channel, session)?;
            return Ok(());
        }
        git.request.extend_from_slice(data);

        let packets = match decode(&git.request) {
            Ok(packets) => packets,
            Err(super::git::packetline::PacketLineError::TruncatedHeader)
            | Err(super::git::packetline::PacketLineError::TruncatedPacket) => {
                self.git_channels.insert(channel, GitChannel::Upload(git));
                return Ok(());
            }
            Err(_) => {
                fail_git_channel(channel, session)?;
                return Ok(());
            }
        };
        if packets == [Packet::Flush] {
            finish_git_channel(channel, 0, session)?;
            return Ok(());
        }

        match self.protocol {
            ProtocolVersion::V0 | ProtocolVersion::V1 => {
                let done = packets.last().is_some_and(
                    |packet| matches!(packet, Packet::Data(line) if trim_line(line) == b"done"),
                );
                if done {
                    match respond_git(self.repositories.clone(), self.protocol, git).await {
                        Some((_, Ok(response))) => {
                            session.data(channel, response)?;
                            finish_git_channel(channel, 0, session)?;
                        }
                        Some((_, Err(_))) | None => fail_git_channel(channel, session)?,
                    }
                } else {
                    self.git_channels.insert(channel, GitChannel::Upload(git));
                }
            }
            ProtocolVersion::V2 => {
                if packets.last() != Some(&Packet::Flush) {
                    self.git_channels.insert(channel, GitChannel::Upload(git));
                    return Ok(());
                }
                let fetch = packets.iter().any(
                    |packet| matches!(packet, Packet::Data(line) if trim_line(line) == b"command=fetch"),
                );
                let done = packets.iter().any(
                    |packet| matches!(packet, Packet::Data(line) if trim_line(line) == b"done"),
                );
                match respond_git(self.repositories.clone(), self.protocol, git).await {
                    Some((mut git, Ok(response))) => {
                        session.data(channel, response)?;
                        if fetch && done {
                            finish_git_channel(channel, 0, session)?;
                        } else {
                            git.request.clear();
                            self.git_channels.insert(channel, GitChannel::Upload(git));
                        }
                    }
                    Some((_, Err(_))) | None => fail_git_channel(channel, session)?,
                }
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.git_channels.remove(&channel);
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(GitChannel::Receive(git)) = self.git_channels.remove(&channel) else {
            return Ok(());
        };
        if !git.commands_complete {
            fail_git_channel(channel, session)?;
            return Ok(());
        }
        let result = finish_receive(self.repositories.clone(), git).await;
        send_receive_result(channel, result, session)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.audit.rejected_exec.fetch_add(1, Ordering::Relaxed);
        session.channel_failure(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.audit.rejected_agent.fetch_add(1, Ordering::Relaxed);
        session.channel_failure(channel)?;
        Ok(false)
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.audit.rejected_forward.fetch_add(1, Ordering::Relaxed);
        Ok(false)
    }

    async fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.audit.rejected_forward.fetch_add(1, Ordering::Relaxed);
        Ok(false)
    }
}

#[derive(Clone, Copy)]
enum RepositoryCommandOutput {
    Human,
    Json,
}

struct RepositoryCreateCommand {
    slug: String,
    object_format: gix::hash::Kind,
    output: RepositoryCommandOutput,
}

fn is_repository_command(command: &[u8]) -> bool {
    command == b"repo" || command.starts_with(b"repo ")
}

fn requests_json(command: &[u8]) -> bool {
    std::str::from_utf8(command).is_ok_and(|command| {
        let tokens = command.split_ascii_whitespace().collect::<Vec<_>>();
        tokens
            .windows(2)
            .any(|tokens| tokens == ["--output", "json"])
    })
}

fn parse_repository_command(command: &[u8]) -> Result<RepositoryCreateCommand, ()> {
    if command.len() > MAX_REPOSITORY_COMMAND_BYTES || !command.is_ascii() {
        return Err(());
    }
    let command = std::str::from_utf8(command).map_err(|_| ())?;
    if command
        .bytes()
        .any(|byte| byte.is_ascii_control() && byte != b' ')
    {
        return Err(());
    }
    let mut tokens = command.split_ascii_whitespace();
    if tokens.next() != Some("repo") || tokens.next() != Some("create") {
        return Err(());
    }
    let slug = tokens.next().ok_or(())?.to_owned();
    let mut object_format = None;
    let mut output = None;
    while let Some(option) = tokens.next() {
        let value = tokens.next().ok_or(())?;
        match option {
            "--object-format" if object_format.is_none() => {
                object_format = Some(match value {
                    "sha1" => gix::hash::Kind::Sha1,
                    "sha256" => gix::hash::Kind::Sha256,
                    _ => return Err(()),
                });
            }
            "--output" if output.is_none() => {
                output = Some(match value {
                    "human" => RepositoryCommandOutput::Human,
                    "json" => RepositoryCommandOutput::Json,
                    _ => return Err(()),
                });
            }
            _ => return Err(()),
        }
    }
    Ok(RepositoryCreateCommand {
        slug,
        object_format: object_format.unwrap_or(gix::hash::Kind::Sha1),
        output: output.unwrap_or(RepositoryCommandOutput::Human),
    })
}

enum RepositoryCommandError {
    Usage,
    Unavailable,
    Create(RepositoryServiceError),
}

async fn run_repository_command(
    repositories: Option<Arc<GitRepositories>>,
    actor: String,
    command: RepositoryCreateCommand,
) -> Result<(crate::store::RepositoryRecord, RepositoryCommandOutput), RepositoryCommandError> {
    let repositories = repositories.ok_or(RepositoryCommandError::Unavailable)?;
    let database = repositories
        .push_database()
        .ok_or(RepositoryCommandError::Unavailable)?
        .to_owned();
    let root = repositories.repository_root().to_owned();
    let permit = repositories
        .blocking_permit()
        .await
        .map_err(|_| RepositoryCommandError::Unavailable)?;
    let output = command.output;
    let correlation_id = format!("{:032x}", rand::random::<u128>());
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        RepositoryService::new(&database, &root)
            .create_for_account(
                &actor,
                &command.slug,
                command.object_format,
                &correlation_id,
            )
            .map(|repository| (repository, output))
            .map_err(RepositoryCommandError::Create)
    })
    .await
    .map_err(|_| RepositoryCommandError::Unavailable)?
}

fn send_repository_command_result(
    channel: ChannelId,
    result: Result<
        (crate::store::RepositoryRecord, RepositoryCommandOutput),
        RepositoryCommandError,
    >,
    machine_requested: bool,
    session: &mut Session,
) -> Result<(), russh::Error> {
    match result {
        Ok((repository, RepositoryCommandOutput::Human)) => {
            session.data(
                channel,
                format!(
                    "Created repository {}/{}.\nObject format: {}\n",
                    repository.owner, repository.slug, repository.object_format
                )
                .into_bytes(),
            )?;
            finish_git_channel(channel, 0, session)
        }
        Ok((repository, RepositoryCommandOutput::Json)) => {
            session.data(
                channel,
                format!(
                    "{{\"version\":1,\"status\":\"success\",\"repository\":{{\"owner\":\"{}\",\"name\":\"{}\",\"object_format\":\"{}\"}}}}\n",
                    repository.owner, repository.slug, repository.object_format
                )
                .into_bytes(),
            )?;
            finish_git_channel(channel, 0, session)
        }
        Err(error) => {
            if machine_requested {
                session.data(
                    channel,
                    format!(
                        "{{\"version\":1,\"status\":\"error\",\"error\":{{\"code\":\"{}\"}}}}\n",
                        repository_command_error_code(&error)
                    )
                    .into_bytes(),
                )?;
            } else {
                session.extended_data(
                    channel,
                    1,
                    format!("tit: {}\n", repository_command_error_message(&error)).into_bytes(),
                )?;
            }
            finish_git_channel(channel, 1, session)
        }
    }
}

fn repository_command_error_code(error: &RepositoryCommandError) -> &'static str {
    match error {
        RepositoryCommandError::Usage => "invalid-command",
        RepositoryCommandError::Unavailable => "service-unavailable",
        RepositoryCommandError::Create(RepositoryServiceError::Store(
            crate::store::StoreError::RepositoryExists(_, _),
        )) => "repository-exists",
        RepositoryCommandError::Create(RepositoryServiceError::Auth(_))
        | RepositoryCommandError::Create(RepositoryServiceError::RepositoryName(_)) => {
            "invalid-name"
        }
        RepositoryCommandError::Create(RepositoryServiceError::Store(
            crate::store::StoreError::AccountNotFound(_),
        )) => "account-unavailable",
        RepositoryCommandError::Create(_) => "repository-create-failed",
    }
}

fn repository_command_error_message(error: &RepositoryCommandError) -> String {
    match repository_command_error_code(error) {
        "invalid-command" => format!("usage: {REPOSITORY_CREATE_USAGE}"),
        "repository-exists" => "A repository with this name already exists.".to_owned(),
        "invalid-name" => "The repository name is not valid.".to_owned(),
        "account-unavailable" => "The account is not active.".to_owned(),
        "service-unavailable" => "The repository service is not available.".to_owned(),
        _ => "The repository could not be created.".to_owned(),
    }
}

impl SshSession {
    fn authorize(&self, public_key: &PublicKey) -> Auth {
        if self.authorized_keys.contains(public_key) {
            Auth::Accept
        } else {
            Auth::reject()
        }
    }

    async fn open_git_service(&mut self, command: &[u8]) -> Option<InitialGitService> {
        let repositories = self.repositories.as_ref()?;
        let identity = self.active_identity()?;
        let service = repositories
            .resolve_ssh_service_for(Some(&identity.username), command)
            .ok()?;
        match service {
            GitSshService::Upload { path, .. } => {
                let permit = repositories.blocking_permit().await.ok()?;
                let protocol = self.protocol;
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let service = UploadPack::open(&path)?;
                    let advertisement = service.advertisement(protocol, false)?;
                    Ok::<_, UploadPackError>(InitialGitService::Upload {
                        service: Box::new(service),
                        advertisement,
                    })
                })
                .await
                .ok()?
                .ok()
            }
            GitSshService::Receive {
                path,
                owner,
                repository,
            } => {
                if !repositories.uses_policy() && !self.authenticated_writer {
                    return None;
                }
                let database = repositories.push_database()?.to_owned();
                let actor = identity.username.clone();
                let public_key = self.authenticated_key.clone()?;
                let permit = repositories.blocking_permit().await.ok()?;
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let service = ReceivePack::open(&path, &database, actor)?;
                    let advertisement = service.advertisement()?;
                    Ok::<_, ReceivePackError>(InitialGitService::Receive(Box::new(
                        InitialReceiveService {
                            service: Box::new(service),
                            advertisement,
                            owner,
                            repository,
                            identity,
                            public_key,
                        },
                    )))
                })
                .await
                .ok()?
                .ok()
            }
        }
    }

    fn active_identity(&self) -> Option<SshIdentity> {
        let public_key = self.authenticated_key.as_ref()?;
        let authenticated = self.authenticated_identity.as_ref()?;
        let current = self.authorized_keys.identity(public_key)?;
        (current == *authenticated).then_some(current)
    }
}

enum InitialGitService {
    Upload {
        service: Box<UploadPack>,
        advertisement: Vec<u8>,
    },
    Receive(Box<InitialReceiveService>),
}

struct InitialReceiveService {
    service: Box<ReceivePack>,
    advertisement: Vec<u8>,
    owner: String,
    repository: String,
    identity: SshIdentity,
    public_key: PublicKey,
}

async fn receive_data(git: &mut ReceiveChannel, data: &[u8]) -> Result<(), ()> {
    if git.commands_complete {
        write_receive_pack(git, data).await?;
        return Ok(());
    }
    git.commands.extend_from_slice(data);
    let boundary = first_flush_end(&git.commands).map_err(|_| ())?;
    let Some(boundary) = boundary else {
        return Ok(());
    };
    let pack = git.commands.split_off(boundary);
    git.commands_complete = true;
    write_receive_pack(git, &pack).await
}

async fn write_receive_pack(git: &mut ReceiveChannel, data: &[u8]) -> Result<(), ()> {
    let bytes = u64::try_from(data.len()).map_err(|_| ())?;
    git.pack_bytes = git.pack_bytes.checked_add(bytes).ok_or(())?;
    if git.pack_bytes > MAX_RECEIVE_PACK_BYTES {
        return Err(());
    }
    git.pack.write_all(data).await.map_err(|_| ())
}

type ReceiveResult = Option<Result<Vec<u8>, (ReceivePackError, Vec<u8>)>>;

async fn finish_receive(
    repositories: Option<Arc<GitRepositories>>,
    git: Box<ReceiveChannel>,
) -> ReceiveResult {
    let ReceiveChannel {
        mut service,
        owner,
        repository,
        identity,
        public_key,
        authorized_keys,
        commands,
        mut pack,
        ..
    } = *git;
    pack.flush().await.ok()?;
    pack.sync_all().await.ok()?;
    drop(pack);
    let repositories = repositories?;
    let push_permit = repositories.push_permit().await.ok()?;
    let permit = repositories.blocking_permit().await.ok()?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _push_permit = push_permit;
        if authorized_keys.identity(&public_key).as_ref() != Some(&identity)
            || !repositories.authorize(
                &identity.username,
                &owner,
                &repository,
                RepositoryOperation::Write,
            )
        {
            return None;
        }
        Some(match service.finish(&commands) {
            Ok(response) => Ok(response),
            Err(error) => {
                let response = service.rejection_response(&commands, &error);
                match service.record_rejection() {
                    Ok(()) => Err((error, response)),
                    Err(audit_error) => {
                        let response = service.rejection_response(&commands, &audit_error);
                        Err((audit_error, response))
                    }
                }
            }
        })
    })
    .await
    .ok()
    .flatten()
}

fn send_receive_result(
    channel: ChannelId,
    result: ReceiveResult,
    session: &mut Session,
) -> Result<(), russh::Error> {
    match result {
        Some(Ok(response)) => {
            session.data(channel, response)?;
            finish_git_channel(channel, 0, session)
        }
        Some(Err((error, response))) => {
            eprintln!("tit: receive-pack failed: {error}");
            session.data(
                channel,
                if response.is_empty() {
                    receive_error_response()
                } else {
                    response
                },
            )?;
            finish_git_channel(channel, 1, session)
        }
        None => {
            session.data(channel, receive_error_response())?;
            finish_git_channel(channel, 1, session)
        }
    }
}

fn receive_error_response() -> Vec<u8> {
    let mut response = Vec::new();
    let _ = encode_data(b"unpack tit rejected the push\n", &mut response);
    super::git::packetline::encode_flush(&mut response);
    response
}

async fn respond_git(
    repositories: Option<Arc<GitRepositories>>,
    protocol: ProtocolVersion,
    git: Box<UploadChannel>,
) -> Option<(Box<UploadChannel>, Result<Vec<u8>, UploadPackError>)> {
    let permit = repositories?.blocking_permit().await.ok()?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let response = git.service.respond(protocol, &git.request);
        (git, response)
    })
    .await
    .ok()
}

fn valid_git_protocol(value: &str) -> bool {
    matches!(value, "version=0" | "version=1" | "version=2")
}

fn trim_line(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

fn finish_git_channel(
    channel: ChannelId,
    status: u32,
    session: &mut Session,
) -> Result<(), russh::Error> {
    session.exit_status_request(channel, status)?;
    session.eof(channel)?;
    session.close(channel)?;
    Ok(())
}

fn fail_git_channel(channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
    let mut error = Vec::new();
    encode_data(b"ERR invalid Git request\n", &mut error)
        .expect("a Git error packet is within the limit");
    session.data(channel, error)?;
    finish_git_channel(channel, 1, session)
}

#[derive(Default)]
struct RequestAudit {
    accepted_env: AtomicUsize,
    rejected_env: AtomicUsize,
    accepted_exec: AtomicUsize,
    rejected_exec: AtomicUsize,
    rejected_shell: AtomicUsize,
    rejected_pty: AtomicUsize,
    rejected_agent: AtomicUsize,
    rejected_forward: AtomicUsize,
}

impl RequestAudit {
    fn snapshot(&self) -> RequestAuditSnapshot {
        RequestAuditSnapshot {
            accepted_env: self.accepted_env.load(Ordering::Relaxed),
            rejected_env: self.rejected_env.load(Ordering::Relaxed),
            accepted_exec: self.accepted_exec.load(Ordering::Relaxed),
            rejected_exec: self.rejected_exec.load(Ordering::Relaxed),
            rejected_shell: self.rejected_shell.load(Ordering::Relaxed),
            rejected_pty: self.rejected_pty.load(Ordering::Relaxed),
            rejected_agent: self.rejected_agent.load(Ordering::Relaxed),
            rejected_forward: self.rejected_forward.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RequestAuditSnapshot {
    pub(crate) accepted_env: usize,
    pub(crate) rejected_env: usize,
    pub(crate) accepted_exec: usize,
    pub(crate) rejected_exec: usize,
    pub(crate) rejected_shell: usize,
    pub(crate) rejected_pty: usize,
    pub(crate) rejected_agent: usize,
    pub(crate) rejected_forward: usize,
}
