use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::JoinHandle;

use crate::auth::SshPublicKey;
use crate::git::packetline::{MAX_REQUEST_BYTES, Packet, decode, encode_data, first_flush_end};
use crate::git::receive_pack::{ReceivePack, ReceivePackError};
use crate::git::transport::{GitRepositories, GitSshService};
use crate::git::upload_pack::{ProtocolVersion, UploadPack, UploadPackError};
use crate::issue::{IssueError, IssueService, MAX_BODY_BYTES, MAX_TITLE_BYTES};
use crate::policy::RepositoryOperation;
use crate::rate_limit::AttemptLimiter;
use crate::repository::{RepositoryService, RepositoryServiceError};
use crate::store::{Store, StoreError};

const VERSION_COMMAND: &[u8] = b"tit --version";
const GIT_PROTOCOL_VARIABLE: &str = "GIT_PROTOCOL";
const MAX_RECEIVE_PACK_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REPOSITORY_COMMAND_BYTES: usize = 512;
const MAX_ISSUE_COMMAND_BYTES: usize = 512;
const MAX_PULL_REQUEST_COMMAND_BYTES: usize = 512;
const MAX_ISSUE_INPUT_BYTES: usize = MAX_TITLE_BYTES + 1 + MAX_BODY_BYTES;
const SSH_ATTEMPTS_PER_MINUTE: usize = 30;
const MAX_SSH_CLIENTS: usize = 4096;
const REPOSITORY_CREATE_USAGE: &str =
    "repo create NAME [--object-format sha1|sha256] [--output human|json]";
const ISSUE_LIST_USAGE: &str = "issue list OWNER/REPOSITORY [--output human|json]";
const ISSUE_CREATE_USAGE: &str = "issue create OWNER/REPOSITORY [--output human|json]";
const PULL_REQUEST_CHECKOUT_USAGE: &str =
    "pr checkout OWNER/REPOSITORY NUMBER [--output human|json]";

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
        max_connections: usize,
    ) -> Result<Self, SshServerError> {
        recover_pushes(&repositories).await?;
        Self::start_inner_with_keys(
            address,
            authorized_keys,
            &[],
            Some(repositories),
            host_key,
            max_connections,
        )
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
            1024,
        )
        .await
    }

    async fn start_inner_with_keys(
        address: SocketAddr,
        authorized_keys: AuthorizedSshKeys,
        writable_keys: &[SshPublicKey],
        repositories: Option<GitRepositories>,
        host_key: PrivateKey,
        max_connections: usize,
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
            connections: Arc::new(Semaphore::new(max_connections)),
            attempts: AttemptLimiter::new(
                SSH_ATTEMPTS_PER_MINUTE,
                Duration::from_secs(60),
                MAX_SSH_CLIENTS,
            ),
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

    pub(crate) async fn shutdown_bounded(
        mut self,
        limit: Duration,
    ) -> Result<bool, SshServerError> {
        self.handle.shutdown("tit shutdown".to_owned());
        match tokio::time::timeout(limit, &mut self.task).await {
            Ok(result) => {
                result.map_err(|_| SshServerError::Join)??;
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
    connections: Arc<Semaphore>,
    attempts: AttemptLimiter<IpAddr>,
}

impl Server for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, peer_address: Option<SocketAddr>) -> Self::Handler {
        SshSession {
            authorized_keys: self.authorized_keys.clone(),
            writable_keys: Arc::clone(&self.writable_keys),
            audit: Arc::clone(&self.audit),
            repositories: self.repositories.clone(),
            protocol: ProtocolVersion::V0,
            exec_channels: HashMap::new(),
            authenticated_identity: None,
            authenticated_key: None,
            authenticated_writer: false,
            peer_address: peer_address
                .map(|address| address.ip())
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            attempts: self.attempts.clone(),
            _connection_permit: self.connections.clone().try_acquire_owned().ok(),
        }
    }
}

struct SshSession {
    authorized_keys: AuthorizedSshKeys,
    writable_keys: Arc<HashSet<PublicKey>>,
    audit: Arc<RequestAudit>,
    repositories: Option<Arc<GitRepositories>>,
    protocol: ProtocolVersion,
    exec_channels: HashMap<ChannelId, ExecChannel>,
    authenticated_identity: Option<SshIdentity>,
    authenticated_key: Option<PublicKey>,
    authenticated_writer: bool,
    peer_address: IpAddr,
    attempts: AttemptLimiter<IpAddr>,
    _connection_permit: Option<OwnedSemaphorePermit>,
}

enum ExecChannel {
    Upload(Box<UploadChannel>),
    Receive(Box<ReceiveChannel>),
    IssueCreate(IssueCreateChannel),
}

struct IssueCreateChannel {
    actor: String,
    owner: String,
    repository: String,
    output: CommandOutput,
    input: Vec<u8>,
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
    maintenance: tokio::sync::OwnedRwLockReadGuard<()>,
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
        if self._connection_permit.is_none() || !self.attempts.allow(self.peer_address) {
            return Ok(Auth::reject());
        }
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
        } else if is_issue_command(command) {
            self.audit.accepted_exec.fetch_add(1, Ordering::Relaxed);
            session.channel_success(channel)?;
            let machine_requested = requests_json(command);
            match (parse_issue_command(command), self.active_identity()) {
                (Ok(IssueCommand::List(command)), Some(identity)) => {
                    let result =
                        run_issue_list(self.repositories.clone(), identity.username, command).await;
                    send_issue_list_result(channel, result, machine_requested, session)?;
                }
                (Ok(IssueCommand::Create(command)), Some(identity)) => {
                    self.exec_channels.insert(
                        channel,
                        ExecChannel::IssueCreate(IssueCreateChannel {
                            actor: identity.username,
                            owner: command.owner,
                            repository: command.repository,
                            output: command.output,
                            input: Vec::new(),
                        }),
                    );
                }
                (Ok(_), None) => send_issue_error(
                    channel,
                    IssueCommandError::Unavailable,
                    machine_requested,
                    session,
                )?,
                (Err(()), _) => send_issue_error(
                    channel,
                    IssueCommandError::Usage,
                    machine_requested,
                    session,
                )?,
            }
        } else if is_pull_request_command(command) {
            self.audit.accepted_exec.fetch_add(1, Ordering::Relaxed);
            session.channel_success(channel)?;
            let machine_requested = requests_json(command);
            let result = match (parse_pull_request_command(command), self.active_identity()) {
                (Ok(command), Some(identity)) => {
                    run_pull_request_checkout(self.repositories.clone(), identity.username, command)
                        .await
                }
                (Ok(_), None) => Err(PullRequestCommandError::Unavailable),
                (Err(()), _) => Err(PullRequestCommandError::Usage),
            };
            send_pull_request_result(channel, result, machine_requested, session)?;
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
                        self.exec_channels.insert(
                            channel,
                            ExecChannel::Upload(Box::new(UploadChannel {
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
                            maintenance,
                        } = *receive;
                        session.data(channel, advertisement)?;
                        let pack = tokio::fs::File::create(service.incoming_pack()).await;
                        match pack {
                            Ok(pack) => {
                                self.exec_channels.insert(
                                    channel,
                                    ExecChannel::Receive(Box::new(ReceiveChannel {
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
                                        maintenance,
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
        let Some(exec) = self.exec_channels.remove(&channel) else {
            return Ok(());
        };
        let mut git = match exec {
            ExecChannel::IssueCreate(mut issue) => {
                if append_issue_input(&mut issue.input, data).is_err() {
                    send_issue_error(
                        channel,
                        IssueCommandError::Input,
                        issue.output == CommandOutput::Json,
                        session,
                    )?;
                } else {
                    self.exec_channels
                        .insert(channel, ExecChannel::IssueCreate(issue));
                }
                return Ok(());
            }
            ExecChannel::Upload(git) => git,
            ExecChannel::Receive(mut git) => {
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
                    self.exec_channels
                        .insert(channel, ExecChannel::Receive(git));
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
                self.exec_channels.insert(channel, ExecChannel::Upload(git));
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
                    self.exec_channels.insert(channel, ExecChannel::Upload(git));
                }
            }
            ProtocolVersion::V2 => {
                if packets.last() != Some(&Packet::Flush) {
                    self.exec_channels.insert(channel, ExecChannel::Upload(git));
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
                            self.exec_channels.insert(channel, ExecChannel::Upload(git));
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
        self.exec_channels.remove(&channel);
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.exec_channels.remove(&channel) {
            Some(ExecChannel::Receive(git)) => {
                if !git.commands_complete {
                    fail_git_channel(channel, session)?;
                    return Ok(());
                }
                let result = finish_receive(self.repositories.clone(), git).await;
                send_receive_result(channel, result, session)?;
            }
            Some(ExecChannel::IssueCreate(issue)) => {
                let active = self
                    .active_identity()
                    .is_some_and(|identity| identity.username == issue.actor);
                let machine_requested = issue.output == CommandOutput::Json;
                let result = if active {
                    run_issue_create(self.repositories.clone(), issue).await
                } else {
                    Err(IssueCommandError::Unavailable)
                };
                send_issue_create_result(channel, result, machine_requested, session)?;
            }
            Some(ExecChannel::Upload(_)) | None => {}
        }
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum CommandOutput {
    Human,
    Json,
}

struct RepositoryCreateCommand {
    slug: String,
    object_format: gix::hash::Kind,
    output: CommandOutput,
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
                    "human" => CommandOutput::Human,
                    "json" => CommandOutput::Json,
                    _ => return Err(()),
                });
            }
            _ => return Err(()),
        }
    }
    Ok(RepositoryCreateCommand {
        slug,
        object_format: object_format.unwrap_or(gix::hash::Kind::Sha1),
        output: output.unwrap_or(CommandOutput::Human),
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
) -> Result<(crate::store::RepositoryRecord, CommandOutput), RepositoryCommandError> {
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
    result: Result<(crate::store::RepositoryRecord, CommandOutput), RepositoryCommandError>,
    machine_requested: bool,
    session: &mut Session,
) -> Result<(), russh::Error> {
    match result {
        Ok((repository, CommandOutput::Human)) => {
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
        Ok((repository, CommandOutput::Json)) => {
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

enum IssueCommand {
    List(IssueListCommand),
    Create(IssueCreateCommand),
}

struct IssueListCommand {
    owner: String,
    repository: String,
    output: CommandOutput,
}

struct IssueCreateCommand {
    owner: String,
    repository: String,
    output: CommandOutput,
}

struct IssueListResult {
    repository: crate::store::RepositoryRecord,
    issues: Vec<crate::store::IssueRecord>,
    output: CommandOutput,
}

struct IssueCreateResult {
    owner: String,
    repository: String,
    issue: crate::store::IssueRecord,
    output: CommandOutput,
}

enum IssueCommandError {
    Usage,
    Input,
    Unavailable,
    Service(IssueError),
}

fn is_issue_command(command: &[u8]) -> bool {
    command == b"issue" || command.starts_with(b"issue ")
}

fn parse_issue_command(command: &[u8]) -> Result<IssueCommand, ()> {
    if command.len() > MAX_ISSUE_COMMAND_BYTES || !command.is_ascii() {
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
    if tokens.next() != Some("issue") {
        return Err(());
    }
    let operation = tokens.next().ok_or(())?;
    let target = tokens.next().ok_or(())?;
    let (owner, repository) = target.split_once('/').ok_or(())?;
    if owner.is_empty() || repository.is_empty() || repository.contains('/') {
        return Err(());
    }
    let output = parse_output_options(tokens)?;
    match operation {
        "list" => Ok(IssueCommand::List(IssueListCommand {
            owner: owner.to_owned(),
            repository: repository.to_owned(),
            output,
        })),
        "create" => Ok(IssueCommand::Create(IssueCreateCommand {
            owner: owner.to_owned(),
            repository: repository.to_owned(),
            output,
        })),
        _ => Err(()),
    }
}

fn parse_output_options<'a>(
    mut tokens: impl Iterator<Item = &'a str>,
) -> Result<CommandOutput, ()> {
    let mut output = None;
    while let Some(option) = tokens.next() {
        let value = tokens.next().ok_or(())?;
        if option != "--output" || output.is_some() {
            return Err(());
        }
        output = Some(match value {
            "human" => CommandOutput::Human,
            "json" => CommandOutput::Json,
            _ => return Err(()),
        });
    }
    Ok(output.unwrap_or(CommandOutput::Human))
}

async fn run_issue_list(
    repositories: Option<Arc<GitRepositories>>,
    actor: String,
    command: IssueListCommand,
) -> Result<IssueListResult, IssueCommandError> {
    let repositories = repositories.ok_or(IssueCommandError::Unavailable)?;
    let database = repositories
        .push_database()
        .ok_or(IssueCommandError::Unavailable)?
        .to_owned();
    let permit = repositories
        .blocking_permit()
        .await
        .map_err(|_| IssueCommandError::Unavailable)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        IssueService::new(&database)
            .list(&command.owner, &command.repository, Some(&actor))
            .map(|(repository, issues)| IssueListResult {
                repository,
                issues,
                output: command.output,
            })
            .map_err(IssueCommandError::Service)
    })
    .await
    .map_err(|_| IssueCommandError::Unavailable)?
}

async fn run_issue_create(
    repositories: Option<Arc<GitRepositories>>,
    command: IssueCreateChannel,
) -> Result<IssueCreateResult, IssueCommandError> {
    let (title, body) = parse_issue_input(&command.input)?;
    let repositories = repositories.ok_or(IssueCommandError::Unavailable)?;
    let database = repositories
        .push_database()
        .ok_or(IssueCommandError::Unavailable)?
        .to_owned();
    let permit = repositories
        .blocking_permit()
        .await
        .map_err(|_| IssueCommandError::Unavailable)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        IssueService::new(&database)
            .create(
                &command.owner,
                &command.repository,
                &command.actor,
                &title,
                &body,
            )
            .map(|issue| IssueCreateResult {
                owner: command.owner,
                repository: command.repository,
                issue,
                output: command.output,
            })
            .map_err(IssueCommandError::Service)
    })
    .await
    .map_err(|_| IssueCommandError::Unavailable)?
}

fn parse_issue_input(input: &[u8]) -> Result<(String, String), IssueCommandError> {
    let (title, body) = input
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or((input, &[][..]), |end| (&input[..end], &input[end + 1..]));
    let title = title.strip_suffix(b"\r").unwrap_or(title);
    Ok((
        std::str::from_utf8(title)
            .map_err(|_| IssueCommandError::Input)?
            .to_owned(),
        std::str::from_utf8(body)
            .map_err(|_| IssueCommandError::Input)?
            .to_owned(),
    ))
}

fn append_issue_input(input: &mut Vec<u8>, data: &[u8]) -> Result<(), ()> {
    if input.len().saturating_add(data.len()) > MAX_ISSUE_INPUT_BYTES {
        return Err(());
    }
    input.extend_from_slice(data);
    Ok(())
}

fn send_issue_list_result(
    channel: ChannelId,
    result: Result<IssueListResult, IssueCommandError>,
    machine_requested: bool,
    session: &mut Session,
) -> Result<(), russh::Error> {
    match result {
        Ok(result) => {
            let data = match result.output {
                CommandOutput::Human => issue_list_human(&result),
                CommandOutput::Json => issue_list_json(&result),
            };
            session.data(channel, data)?;
            finish_git_channel(channel, 0, session)
        }
        Err(error) => send_issue_error(channel, error, machine_requested, session),
    }
}

fn issue_list_human(result: &IssueListResult) -> Vec<u8> {
    if result.issues.is_empty() {
        return b"No issues.\n".to_vec();
    }
    let mut output = String::new();
    for issue in &result.issues {
        output.push_str(&format!(
            "#{} {} {}\n",
            issue.number, issue.state, issue.title
        ));
    }
    output.into_bytes()
}

fn issue_list_json(result: &IssueListResult) -> Vec<u8> {
    let issues = result
        .issues
        .iter()
        .map(|issue| {
            serde_json::json!({
                "number": issue.number,
                "title": issue.title,
                "state": issue.state,
                "author": issue.author,
                "created_at": issue.created_at,
                "updated_at": issue.updated_at,
            })
        })
        .collect::<Vec<_>>();
    json_line(serde_json::json!({
        "version": 1,
        "status": "success",
        "repository": {
            "owner": result.repository.owner,
            "name": result.repository.slug,
        },
        "issues": issues,
    }))
}

fn send_issue_create_result(
    channel: ChannelId,
    result: Result<IssueCreateResult, IssueCommandError>,
    machine_requested: bool,
    session: &mut Session,
) -> Result<(), russh::Error> {
    match result {
        Ok(result) => {
            let data = match result.output {
                CommandOutput::Human => format!(
                    "Created issue {}/{}#{}.\n",
                    result.owner, result.repository, result.issue.number
                )
                .into_bytes(),
                CommandOutput::Json => json_line(serde_json::json!({
                    "version": 1,
                    "status": "success",
                    "repository": {
                        "owner": result.owner,
                        "name": result.repository,
                    },
                    "issue": {
                        "number": result.issue.number,
                        "title": result.issue.title,
                        "state": result.issue.state,
                        "author": result.issue.author,
                        "created_at": result.issue.created_at,
                        "updated_at": result.issue.updated_at,
                    },
                })),
            };
            session.data(channel, data)?;
            finish_git_channel(channel, 0, session)
        }
        Err(error) => send_issue_error(channel, error, machine_requested, session),
    }
}

fn send_issue_error(
    channel: ChannelId,
    error: IssueCommandError,
    machine_requested: bool,
    session: &mut Session,
) -> Result<(), russh::Error> {
    if machine_requested {
        session.data(
            channel,
            json_line(serde_json::json!({
                "version": 1,
                "status": "error",
                "error": { "code": issue_command_error_code(&error) },
            })),
        )?;
    } else {
        session.extended_data(
            channel,
            1,
            format!("tit: {}\n", issue_command_error_message(&error)).into_bytes(),
        )?;
    }
    finish_git_channel(channel, 1, session)
}

fn json_line(value: serde_json::Value) -> Vec<u8> {
    let mut output = serde_json::to_vec(&value).expect("a JSON value can be serialized");
    output.push(b'\n');
    output
}

fn issue_command_error_code(error: &IssueCommandError) -> &'static str {
    match error {
        IssueCommandError::Usage => "invalid-command",
        IssueCommandError::Input
        | IssueCommandError::Service(IssueError::Title | IssueError::Body) => "invalid-input",
        IssueCommandError::Service(IssueError::Auth(_) | IssueError::RepositoryName(_)) => {
            "invalid-target"
        }
        IssueCommandError::Service(IssueError::Store(
            crate::store::StoreError::RepositoryNotFound(_, _)
            | crate::store::StoreError::IssueHidden,
        )) => "repository-unavailable",
        IssueCommandError::Service(IssueError::Store(crate::store::StoreError::IssueDenied)) => {
            "permission-denied"
        }
        IssueCommandError::Service(IssueError::Store(
            crate::store::StoreError::AccountNotFound(_),
        )) => "account-unavailable",
        IssueCommandError::Unavailable => "service-unavailable",
        IssueCommandError::Service(_) => "issue-command-failed",
    }
}

fn issue_command_error_message(error: &IssueCommandError) -> String {
    match issue_command_error_code(error) {
        "invalid-command" => format!("usage: {ISSUE_LIST_USAGE} or {ISSUE_CREATE_USAGE}"),
        "invalid-input" => {
            "The first input line must be a valid title. The remaining input is the body."
                .to_owned()
        }
        "invalid-target" => "The repository name is not valid.".to_owned(),
        "repository-unavailable" => "The repository is not available.".to_owned(),
        "permission-denied" => "The account cannot create an issue in this repository.".to_owned(),
        "account-unavailable" => "The account is not active.".to_owned(),
        "service-unavailable" => "The issue service is not available.".to_owned(),
        _ => "The issue command could not be completed.".to_owned(),
    }
}

struct PullRequestCheckoutCommand {
    owner: String,
    repository: String,
    number: i64,
    output: CommandOutput,
}

struct PullRequestCheckoutResult {
    owner: String,
    repository: String,
    number: i64,
    output: CommandOutput,
}

enum PullRequestCommandError {
    Usage,
    Unavailable,
    Store(StoreError),
}

fn is_pull_request_command(command: &[u8]) -> bool {
    command == b"pr" || command.starts_with(b"pr ")
}

fn parse_pull_request_command(command: &[u8]) -> Result<PullRequestCheckoutCommand, ()> {
    if command.len() > MAX_PULL_REQUEST_COMMAND_BYTES || !command.is_ascii() {
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
    if tokens.next() != Some("pr") || tokens.next() != Some("checkout") {
        return Err(());
    }
    let target = tokens.next().ok_or(())?;
    let (owner, repository) = target.split_once('/').ok_or(())?;
    if owner.is_empty() || repository.is_empty() || repository.contains('/') {
        return Err(());
    }
    let number = tokens.next().ok_or(())?.parse::<i64>().map_err(|_| ())?;
    if number < 1 {
        return Err(());
    }
    let output = parse_output_options(tokens)?;
    Ok(PullRequestCheckoutCommand {
        owner: owner.to_owned(),
        repository: repository.to_owned(),
        number,
        output,
    })
}

async fn run_pull_request_checkout(
    repositories: Option<Arc<GitRepositories>>,
    actor: String,
    command: PullRequestCheckoutCommand,
) -> Result<PullRequestCheckoutResult, PullRequestCommandError> {
    let repositories = repositories.ok_or(PullRequestCommandError::Unavailable)?;
    let database = repositories
        .push_database()
        .ok_or(PullRequestCommandError::Unavailable)?
        .to_owned();
    let permit = repositories
        .blocking_permit()
        .await
        .map_err(|_| PullRequestCommandError::Unavailable)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        Store::open(&database)
            .and_then(|store| {
                store.pull_request(
                    &command.owner,
                    &command.repository,
                    command.number,
                    Some(&actor),
                )
            })
            .map(|_| PullRequestCheckoutResult {
                owner: command.owner,
                repository: command.repository,
                number: command.number,
                output: command.output,
            })
            .map_err(PullRequestCommandError::Store)
    })
    .await
    .map_err(|_| PullRequestCommandError::Unavailable)?
}

fn send_pull_request_result(
    channel: ChannelId,
    result: Result<PullRequestCheckoutResult, PullRequestCommandError>,
    machine_requested: bool,
    session: &mut Session,
) -> Result<(), russh::Error> {
    match result {
        Ok(result) => {
            let fetch = format!(
                "git fetch origin refs/pull/{}/head:refs/heads/pr-{}",
                result.number, result.number
            );
            let checkout = format!("git checkout pr-{}", result.number);
            let data = match result.output {
                CommandOutput::Human => format!("{fetch}\n{checkout}\n"),
                CommandOutput::Json => format!(
                    "{{\"version\":1,\"status\":\"success\",\"repository\":{{\"owner\":\"{}\",\"name\":\"{}\"}},\"pull_request\":{{\"number\":{},\"ref\":\"refs/pull/{}/head\",\"local_branch\":\"pr-{}\"}},\"commands\":{{\"fetch\":\"{}\",\"checkout\":\"{}\"}}}}\n",
                    result.owner,
                    result.repository,
                    result.number,
                    result.number,
                    result.number,
                    fetch,
                    checkout,
                ),
            };
            session.data(channel, data.into_bytes())?;
            finish_git_channel(channel, 0, session)
        }
        Err(error) => {
            if machine_requested {
                session.data(
                    channel,
                    format!(
                        "{{\"version\":1,\"status\":\"error\",\"error\":{{\"code\":\"{}\"}}}}\n",
                        pull_request_command_error_code(&error)
                    )
                    .into_bytes(),
                )?;
            } else {
                session.extended_data(
                    channel,
                    1,
                    format!("tit: {}\n", pull_request_command_error_message(&error)).into_bytes(),
                )?;
            }
            finish_git_channel(channel, 1, session)
        }
    }
}

fn pull_request_command_error_code(error: &PullRequestCommandError) -> &'static str {
    match error {
        PullRequestCommandError::Usage => "invalid-command",
        PullRequestCommandError::Unavailable => "service-unavailable",
        PullRequestCommandError::Store(
            StoreError::PullRequestHidden
            | StoreError::PullRequestNotFound(_, _, _)
            | StoreError::RepositoryNotFound(_, _),
        ) => "pull-request-unavailable",
        PullRequestCommandError::Store(_) => "pull-request-checkout-failed",
    }
}

fn pull_request_command_error_message(error: &PullRequestCommandError) -> String {
    match pull_request_command_error_code(error) {
        "invalid-command" => format!("usage: {PULL_REQUEST_CHECKOUT_USAGE}"),
        "pull-request-unavailable" => "The pull request is not available.".to_owned(),
        "invalid-target" => "The pull-request target is not valid.".to_owned(),
        "service-unavailable" => "The pull-request service is not available.".to_owned(),
        _ => "The pull-request checkout command could not be completed.".to_owned(),
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
                let uses_policy = repositories.uses_policy();
                let maintenance = repositories.mutation_permit().await;
                let permit = repositories.blocking_permit().await.ok()?;
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let service = if uses_policy {
                        ReceivePack::open_authorized(
                            &path,
                            &database,
                            actor,
                            owner.clone(),
                            repository.clone(),
                        )?
                    } else {
                        ReceivePack::open(&path, &database, actor)?
                    };
                    let advertisement = service.advertisement()?;
                    Ok::<_, ReceivePackError>(InitialGitService::Receive(Box::new(
                        InitialReceiveService {
                            service: Box::new(service),
                            advertisement,
                            owner,
                            repository,
                            identity,
                            public_key,
                            maintenance,
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
    maintenance: tokio::sync::OwnedRwLockReadGuard<()>,
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
        maintenance,
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
        let _maintenance = maintenance;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_bounded_issue_commands_and_input() {
        assert!(matches!(
            parse_issue_command(b"issue list alice/project --output json"),
            Ok(IssueCommand::List(_))
        ));
        assert!(matches!(
            parse_issue_command(b"issue create alice/project"),
            Ok(IssueCommand::Create(_))
        ));
        for command in [
            b"issue list alice/project --output json extra".as_slice(),
            b"issue list alice/project/extra".as_slice(),
            b"issue create alice/project --output json --output json".as_slice(),
            &[b'x'; MAX_ISSUE_COMMAND_BYTES + 1],
        ] {
            assert!(parse_issue_command(command).is_err());
        }

        let mut input = Vec::new();
        assert!(append_issue_input(&mut input, &[b'x'; MAX_ISSUE_INPUT_BYTES]).is_ok());
        assert!(append_issue_input(&mut input, b"x").is_err());
        assert!(matches!(
            parse_issue_input(b"invalid\xff"),
            Err(IssueCommandError::Input)
        ));
    }

    #[test]
    fn parses_only_bounded_pull_request_checkout_commands() {
        let command = parse_pull_request_command(b"pr checkout alice/project 42 --output json")
            .expect("parse a pull-request checkout command");
        assert_eq!(command.owner, "alice");
        assert_eq!(command.repository, "project");
        assert_eq!(command.number, 42);
        assert!(command.output == CommandOutput::Json);
        for command in [
            b"pr checkout alice/project 0".as_slice(),
            b"pr checkout alice/project not-a-number".as_slice(),
            b"pr checkout alice/project/extra 1".as_slice(),
            b"pr checkout alice/project 1 --output json extra".as_slice(),
            b"pr checkout alice/project 1 --output json --output json".as_slice(),
            &[b'x'; MAX_PULL_REQUEST_COMMAND_BYTES + 1],
        ] {
            assert!(parse_pull_request_command(command).is_err());
        }
    }
}
