use crate::{auth, git, maintenance, ssh, store};

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use auth::SshPublicKey;
use git::transport::GitRepositories;
use ssh::RunningSshServer;
use store::Store;
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stock_openssh_authenticates_supported_keys_and_ignores_the_username() {
    for fixture in [KeyFixture::Ed25519, KeyFixture::EcdsaP256] {
        let directory = TempDir::new().expect("create a key directory");
        let private_key = directory.path().join(fixture.name());
        generate_key(&private_key, fixture);
        let key = parse_public_key(&private_key);
        let server = start(&[key]).await;

        for username in ["alice", "the-ssh-user-is-ignored"] {
            let output = ssh(&server, &private_key, username, &["tit --version"]);
            assert!(
                output.status.success(),
                "authenticate {}: {}",
                fixture.name(),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                String::from_utf8(output.stdout).expect("read the version output"),
                format!("tit {}\n", env!("CARGO_PKG_VERSION"))
            );
        }

        assert_eq!(server.audit().accepted_exec, 2);
        server.shutdown().await.expect("stop the SSH server");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_available_commands_and_explains_invalid_commands() {
    let directory = TempDir::new().expect("create a key directory");
    let private_key = directory.path().join("ed25519");
    generate_key(&private_key, KeyFixture::Ed25519);
    let server = start(&[parse_public_key(&private_key)]).await;

    let help = ssh(&server, &private_key, "alice", &["help"]);
    assert!(
        help.status.success(),
        "help failed: {}",
        String::from_utf8_lossy(&help.stderr)
    );
    let help_text = String::from_utf8(help.stdout).expect("read the help output");
    assert!(help_text.contains("Available tit SSH commands:"));
    assert!(help_text.contains("auth ONE-TIME-SECRET"));
    assert!(help_text.contains("repo create NAME"));
    assert!(help_text.contains("org create NAME DISPLAY_NAME"));
    assert!(help_text.contains("org member set ORGANIZATION USER owner|maintainer|writer|reader"));
    assert!(help_text.contains("org member remove ORGANIZATION USER"));
    assert!(!help_text.contains("object-format"));
    assert!(help_text.contains("issue list OWNER/REPOSITORY"));
    assert!(help_text.contains("issue comment OWNER/REPOSITORY NUMBER"));
    assert!(help_text.contains("issue close OWNER/REPOSITORY NUMBER"));
    assert!(help_text.contains("issue reopen OWNER/REPOSITORY NUMBER"));
    assert!(help_text.contains("pr list OWNER/REPOSITORY"));
    assert!(help_text.contains("pr create OWNER/REPOSITORY BASE HEAD"));
    assert!(help_text.contains("pr close OWNER/REPOSITORY NUMBER"));
    assert!(help_text.contains("pr reopen OWNER/REPOSITORY NUMBER"));
    assert!(help_text.contains("pr checkout OWNER/REPOSITORY NUMBER"));

    let invalid = ssh(&server, &private_key, "alice", &["not-a-command"]);
    assert!(!invalid.status.success());
    assert_eq!(
        String::from_utf8(invalid.stderr).expect("read the invalid-command error"),
        "tit: The command is not valid.\nUse 'help' to list the available commands.\n"
    );

    let malformed = ssh(&server, &private_key, "alice", &["repo create"]);
    assert!(!malformed.status.success());
    let malformed_error =
        String::from_utf8(malformed.stderr).expect("read the malformed-command error");
    assert!(malformed_error.contains("usage: repo create NAME"));
    assert!(malformed_error.contains("Use 'help' to list the available commands."));

    let invalid_json = ssh(
        &server,
        &private_key,
        "alice",
        &["not-a-command --output json"],
    );
    assert!(!invalid_json.status.success());
    let response: serde_json::Value =
        serde_json::from_slice(&invalid_json.stdout).expect("parse the JSON error");
    assert_eq!(response["version"], 1);
    assert_eq!(response["status"], "error");
    assert_eq!(response["error"]["code"], "invalid-command");

    server.shutdown().await.expect("stop the SSH server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manages_organizations_as_the_authenticated_account() {
    let directory = TempDir::new().expect("create an organization SSH fixture directory");
    let alice_private = directory.path().join("alice");
    let bob_private = directory.path().join("bob");
    generate_key(&alice_private, KeyFixture::Ed25519);
    generate_key(&bob_private, KeyFixture::Ed25519);
    let database = directory.path().join("tit.sqlite3");
    let repositories_root = directory.path().join("repositories");
    fs::create_dir(&repositories_root).expect("create the repository root");
    let store = Store::open(&database).expect("create the organization database");
    store
        .connection()
        .execute_batch(
            "INSERT INTO account
             (id, username, is_administrator, state, created_at) VALUES
             (1, 'alice', 1, 'active', 1),
             (2, 'bob', 0, 'active', 1);",
        )
        .expect("create organization accounts");
    drop(store);
    let repositories = GitRepositories::new_managed_authorized_with_gate(
        &repositories_root,
        &database,
        maintenance::MaintenanceGate::default(),
    )
    .expect("open the managed repository root");
    let server = RunningSshServer::start_with_account_git(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        vec![
            ("alice".to_owned(), parse_public_key(&alice_private)),
            ("bob".to_owned(), parse_public_key(&bob_private)),
        ],
        repositories,
    )
    .await
    .expect("start the organization SSH server");

    let created = ssh(
        &server,
        &alice_private,
        "ignored",
        &["org create acme Acme Organization --output json"],
    );
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let response: serde_json::Value =
        serde_json::from_slice(&created.stdout).expect("parse the create response");
    assert_eq!(response["action"], "created");
    assert_eq!(response["organization"], "acme");

    let denied = ssh(
        &server,
        &bob_private,
        "alice",
        &["org member set acme bob owner --output json"],
    );
    assert!(!denied.status.success());
    let response: serde_json::Value =
        serde_json::from_slice(&denied.stdout).expect("parse the denied response");
    assert_eq!(response["error"]["code"], "permission-denied");

    let promoted = ssh(
        &server,
        &alice_private,
        "ignored",
        &["org member set acme bob owner"],
    );
    assert!(promoted.status.success());
    assert_eq!(
        String::from_utf8(promoted.stdout).expect("read the member-set response"),
        "Set bob as owner in acme.\n"
    );

    let removed = ssh(
        &server,
        &bob_private,
        "ignored",
        &["org member remove acme alice"],
    );
    assert!(removed.status.success());
    let last_owner = ssh(
        &server,
        &bob_private,
        "ignored",
        &["org member remove acme bob --output json"],
    );
    assert!(!last_owner.status.success());
    let response: serde_json::Value =
        serde_json::from_slice(&last_owner.stdout).expect("parse the last-owner response");
    assert_eq!(response["error"]["code"], "last-owner");

    let profile = Store::open(&database)
        .expect("open the organization database")
        .organization_profile("acme", 1, 20)
        .expect("read the organization");
    assert_eq!(profile.display_name, "Acme Organization");
    assert_eq!(profile.members.len(), 1);
    assert_eq!(profile.members[0].username, "bob");
    assert_eq!(profile.members[0].role, "owner");

    server.shutdown().await.expect("stop the SSH server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_unknown_keys_and_forced_rsa_sha1_authentication() {
    let directory = TempDir::new().expect("create a key directory");
    let authorized_private = directory.path().join("authorized");
    let unknown_private = directory.path().join("unknown");
    generate_key(&authorized_private, KeyFixture::Ed25519);
    generate_key(&unknown_private, KeyFixture::Ed25519);
    let authorized_key = parse_public_key(&authorized_private);
    let server = start(&[authorized_key]).await;

    let unknown = ssh(&server, &unknown_private, "alice", &["tit --version"]);
    assert!(!unknown.status.success());
    server.shutdown().await.expect("stop the SSH server");

    let rsa_private = directory.path().join("rsa");
    generate_key(&rsa_private, KeyFixture::Rsa3072);
    let rsa_server = start(&[parse_public_key(&authorized_private)]).await;
    let rsa_sha1 = ssh(
        &rsa_server,
        &rsa_private,
        "alice",
        &["-o", "PubkeyAcceptedAlgorithms=ssh-rsa", "tit --version"],
    );
    assert!(
        !rsa_sha1.status.success(),
        "the server accepted RSA-SHA1: {}",
        String::from_utf8_lossy(&rsa_sha1.stdout)
    );
    rsa_server
        .shutdown()
        .await
        .expect("stop the RSA SSH server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limits_authentication_attempts_by_client_address() {
    let directory = TempDir::new().expect("create a key directory");
    let private_key = directory.path().join("ed25519");
    generate_key(&private_key, KeyFixture::Ed25519);
    let server = start(&[parse_public_key(&private_key)]).await;

    for attempt in 0..30 {
        let output = ssh(&server, &private_key, "alice", &["tit --version"]);
        assert!(
            output.status.success(),
            "authentication attempt {} failed: {}",
            attempt + 1,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let limited = ssh(&server, &private_key, "alice", &["tit --version"]);
    assert!(!limited.status.success());

    server.shutdown().await.expect("stop the SSH server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_shell_pty_arbitrary_exec_subsystem_agent_and_forwarding() {
    let directory = TempDir::new().expect("create a key directory");
    let private_key = directory.path().join("ed25519");
    generate_key(&private_key, KeyFixture::Ed25519);
    let key = parse_public_key(&private_key);
    let server = start(&[key]).await;

    assert!(!ssh(&server, &private_key, "alice", &[]).status.success());
    assert!(
        !ssh(&server, &private_key, "alice", &["uname", "-a"])
            .status
            .success()
    );
    assert!(
        !ssh(&server, &private_key, "alice", &["-s", "sftp"])
            .status
            .success()
    );
    let pty = ssh(&server, &private_key, "alice", &["-tt", "tit --version"]);
    assert!(
        !pty.status.success() || !pty.stderr.is_empty(),
        "the PTY request was not rejected"
    );
    assert!(
        !ssh(&server, &private_key, "alice", &["-W", "127.0.0.1:1"])
            .status
            .success()
    );
    let agent_socket = directory.path().join("agent.sock");
    let mut agent_process = start_agent(&agent_socket, &private_key);
    let agent = ssh_with_env(
        &server,
        &private_key,
        "alice",
        &["-A", "tit --version"],
        &[(
            "SSH_AUTH_SOCK",
            agent_socket.to_str().expect("a UTF-8 agent socket path"),
        )],
    );
    agent_process.kill().expect("stop the test SSH agent");
    agent_process.wait().expect("wait for the test SSH agent");
    assert!(agent.status.success());

    let audit = server.audit();
    assert!(audit.rejected_shell >= 1);
    assert!(audit.accepted_exec >= 2);
    assert!(audit.rejected_pty >= 1);
    assert!(audit.rejected_agent >= 1);
    assert!(audit.rejected_forward >= 1);
    server.shutdown().await.expect("stop the SSH server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepts_only_strict_git_protocol_environment_values() {
    let directory = TempDir::new().expect("create a key directory");
    let private_key = directory.path().join("ed25519");
    generate_key(&private_key, KeyFixture::Ed25519);
    let key = parse_public_key(&private_key);
    let server = start(&[key]).await;

    for value in ["version=0", "version=1", "version=2"] {
        let output = ssh_with_env(
            &server,
            &private_key,
            "alice",
            &["-o", "SendEnv=GIT_PROTOCOL", "tit --version"],
            &[("GIT_PROTOCOL", value)],
        );
        assert!(output.status.success());
    }
    for value in ["", "2", "version=3", "version=2:extra", "version=2\nBAD=1"] {
        let output = ssh_with_env(
            &server,
            &private_key,
            "alice",
            &["-o", "SendEnv=GIT_PROTOCOL", "tit --version"],
            &[("GIT_PROTOCOL", value)],
        );
        assert!(output.status.success());
    }
    let unrelated = ssh_with_env(
        &server,
        &private_key,
        "alice",
        &["-o", "SendEnv=UNRELATED", "tit --version"],
        &[("UNRELATED", "value")],
    );
    assert!(unrelated.status.success());

    let audit = server.audit();
    assert_eq!(audit.accepted_env, 3);
    assert_eq!(audit.rejected_env, 6);
    server.shutdown().await.expect("stop the SSH server");
}

async fn start(keys: &[SshPublicKey]) -> RunningSshServer {
    RunningSshServer::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), keys)
        .await
        .expect("start the SSH server")
}

fn ssh(
    server: &RunningSshServer,
    private_key: &Path,
    username: &str,
    arguments: &[&str],
) -> Output {
    ssh_with_env(server, private_key, username, arguments, &[])
}

fn ssh_with_env(
    server: &RunningSshServer,
    private_key: &Path,
    username: &str,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> Output {
    let mut command = Command::new("ssh");
    command.args([
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "ConnectTimeout=5",
        "-i",
    ]);
    command.arg(private_key);
    command.args(["-p", &server.address().port().to_string()]);
    command.arg(format!("{username}@{}", server.address().ip()));
    command.args(arguments);
    command.envs(environment.iter().copied());
    command.output().expect("run the stock SSH client")
}

fn parse_public_key(private_key: &Path) -> SshPublicKey {
    let encoded = fs::read_to_string(public_key_path(private_key)).expect("read the public key");
    SshPublicKey::parse(&encoded).expect("parse the public key")
}

fn public_key_path(private_key: &Path) -> PathBuf {
    let mut path = private_key.as_os_str().to_owned();
    path.push(".pub");
    PathBuf::from(path)
}

#[derive(Clone, Copy)]
enum KeyFixture {
    Ed25519,
    EcdsaP256,
    Rsa3072,
}

impl KeyFixture {
    fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 => "ecdsa-p256",
            Self::Rsa3072 => "rsa-3072",
        }
    }
}

fn generate_key(path: &Path, fixture: KeyFixture) {
    let mut command = Command::new("ssh-keygen");
    command.args(["-q", "-N", "", "-f"]);
    command.arg(path);
    match fixture {
        KeyFixture::Ed25519 => {
            command.args(["-t", "ed25519"]);
        }
        KeyFixture::EcdsaP256 => {
            command.args(["-t", "ecdsa", "-b", "256"]);
        }
        KeyFixture::Rsa3072 => {
            command.args(["-t", "rsa", "-b", "3072"]);
        }
    }
    let output = command.output().expect("run ssh-keygen key generation");
    assert!(
        output.status.success(),
        "generate {}: {}",
        fixture.name(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn start_agent(socket: &Path, private_key: &Path) -> Child {
    let mut child = Command::new("ssh-agent")
        .args(["-D", "-a"])
        .arg(socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the stock SSH agent");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        if let Some(status) = child.try_wait().expect("inspect the SSH agent") {
            panic!("SSH agent stopped before it was ready: {status}");
        }
        assert!(Instant::now() < deadline, "SSH agent was not ready");
        thread::sleep(Duration::from_millis(10));
    }

    let output = Command::new("ssh-add")
        .arg(private_key)
        .env("SSH_AUTH_SOCK", socket)
        .output()
        .expect("add the test key to the SSH agent");
    assert!(
        output.status.success(),
        "add the test key to the SSH agent: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    child
}
