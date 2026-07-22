use std::borrow::Cow;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rand::rng;
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Preferred, Pty};
use ssh_key::{Algorithm, EcdsaCurve, PrivateKey, PublicKey};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::auth::SshPublicKey;

const VERSION_COMMAND: &[u8] = b"tit --version";
const GIT_PROTOCOL_VARIABLE: &str = "GIT_PROTOCOL";

pub(crate) struct RunningSshServer {
    address: SocketAddr,
    handle: russh::server::RunningServerHandle,
    task: JoinHandle<std::io::Result<()>>,
    audit: Arc<RequestAudit>,
}

impl RunningSshServer {
    pub(crate) async fn start(
        address: SocketAddr,
        authorized_keys: &[SshPublicKey],
    ) -> Result<Self, SshServerError> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let host_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519)?;
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
        let authorized_keys = Arc::new(
            authorized_keys
                .iter()
                .map(|key| key.public_key().clone())
                .collect(),
        );
        let audit = Arc::new(RequestAudit::default());
        let server = SshServer {
            authorized_keys,
            audit: Arc::clone(&audit),
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
}

#[derive(Clone)]
struct SshServer {
    authorized_keys: Arc<HashSet<PublicKey>>,
    audit: Arc<RequestAudit>,
}

impl Server for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, _peer_address: Option<SocketAddr>) -> Self::Handler {
        SshSession {
            authorized_keys: Arc::clone(&self.authorized_keys),
            audit: Arc::clone(&self.audit),
        }
    }
}

struct SshSession {
    authorized_keys: Arc<HashSet<PublicKey>>,
    audit: Arc<RequestAudit>,
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
        Ok(self.authorize(public_key))
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
        } else {
            self.audit.rejected_exec.fetch_add(1, Ordering::Relaxed);
            session.channel_failure(channel)?;
            session.close(channel)?;
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

impl SshSession {
    fn authorize(&self, public_key: &PublicKey) -> Auth {
        if self.authorized_keys.contains(public_key) {
            Auth::Accept
        } else {
            Auth::reject()
        }
    }
}

fn valid_git_protocol(value: &str) -> bool {
    matches!(value, "version=0" | "version=1" | "version=2")
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
