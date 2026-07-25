use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

mod ssh_fixture;

use ssh_fixture::create_ssh_key;

#[test]
fn serves_an_imported_repository_through_http_and_ssh() {
    let instance = TempDir::new().expect("create an instance directory");
    let http = free_address();
    let ssh = free_address();
    let config = instance.path().join("config.toml");
    fs::write(
        &config,
        format!(
            "version = 1\npublic_url = \"http://{http}/\"\n\n\
             [http]\nlisten = \"{http}\"\n\n\
             [ssh]\nlisten = \"{ssh}\"\npublic_host = \"127.0.0.1\"\npublic_port = {}\n",
            ssh.port()
        ),
    )
    .expect("write the server configuration");

    let private_key = instance.path().join("administrator");
    create_ssh_key(&private_key);
    let public_key = fs::read_to_string(private_key.with_extension("pub"))
        .expect("read the administrator public key");
    run_tit(
        instance.path(),
        &config,
        &["setup", "admin", "alice", public_key.trim()],
    );

    let source = create_source_repository(instance.path());
    run_tit(
        instance.path(),
        &config,
        &[
            "admin",
            "repository",
            "import",
            "alice",
            "example",
            source.to_str().expect("a UTF-8 source path"),
        ],
    );

    let mut server = spawn_server(&config);
    wait_for_listener(http, &mut server);
    wait_for_listener(ssh, &mut server);

    let health = http_get(http, "/healthz");
    assert!(health.starts_with("HTTP/1.1 200"));
    assert!(health.ends_with("\r\n\r\nready\n"));

    let repository = http_get(http, "/alice/example");
    assert!(repository.starts_with("HTTP/1.1 200"));
    assert!(repository.contains("serve fixture"));

    let http_clone = instance.path().join("http-clone");
    run_git(
        instance.path(),
        &[
            "clone",
            "-q",
            &format!("http://{http}/alice/example.git"),
            http_clone.to_str().expect("a UTF-8 clone path"),
        ],
    );
    assert_eq!(
        fs::read(http_clone.join("README.md")).expect("read the HTTP clone"),
        b"serve fixture\n"
    );

    let ssh_clone = instance.path().join("ssh-clone");
    let ssh_command = format!(
        "ssh -F /dev/null -i {} -o BatchMode=yes -o IdentitiesOnly=yes \
         -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR",
        private_key.display()
    );
    let output = Command::new("git")
        .args([
            "clone",
            "-q",
            &format!("ssh://ignored@127.0.0.1:{}/alice/example.git", ssh.port()),
        ])
        .arg(&ssh_clone)
        .env("GIT_SSH_COMMAND", ssh_command)
        .output()
        .expect("clone through the SSH server");
    assert!(
        output.status.success(),
        "SSH clone failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(ssh_clone.join("README.md")).expect("read the SSH clone"),
        b"serve fixture\n"
    );

    server.terminate();
}

fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a temporary port");
    listener.local_addr().expect("read the temporary address")
}

fn create_source_repository(parent: &Path) -> PathBuf {
    let worktree = parent.join("source-worktree");
    run_git(
        parent,
        &[
            "init",
            "-q",
            "-b",
            "main",
            worktree.to_str().expect("a UTF-8 worktree path"),
        ],
    );
    fs::write(worktree.join("README.md"), b"serve fixture\n").expect("write source content");
    run_git(&worktree, &["add", "."]);

    let output = Command::new("git")
        .args(["commit", "-q", "-m", "initial"])
        .env("GIT_AUTHOR_NAME", "Tit Test")
        .env("GIT_AUTHOR_EMAIL", "tit@example.test")
        .env("GIT_COMMITTER_NAME", "Tit Test")
        .env("GIT_COMMITTER_EMAIL", "tit@example.test")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "commit.gpgsign")
        .env("GIT_CONFIG_VALUE_0", "false")
        .current_dir(&worktree)
        .output()
        .expect("commit source content");
    assert!(
        output.status.success(),
        "Git commit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bare = parent.join("source.git");
    run_git(
        parent,
        &[
            "clone",
            "-q",
            "--bare",
            worktree.to_str().expect("a UTF-8 worktree path"),
            bare.to_str().expect("a UTF-8 bare path"),
        ],
    );
    bare
}

fn run_git(directory: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(directory)
        .output()
        .expect("run Git");
    assert!(
        output.status.success(),
        "Git command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_tit(directory: &Path, config: &Path, arguments: &[&str]) {
    let output = Command::new(tit_binary())
        .arg("--config")
        .arg(config)
        .args(arguments)
        .current_dir(directory)
        .output()
        .expect("run tit");
    assert!(
        output.status.success(),
        "tit command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn tit_binary() -> PathBuf {
    env::var_os("TIT_RELEASE_BINARY")
        .map(Into::into)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_tit").into())
}

fn spawn_server(config: &Path) -> ChildGuard {
    let child = Command::new(tit_binary())
        .arg("--config")
        .arg(config)
        .arg("serve")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the tit server");
    ChildGuard(Some(child))
}

fn wait_for_listener(address: SocketAddr, server: &mut ChildGuard) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(address).is_ok() {
            return;
        }
        if let Some(status) = server
            .0
            .as_mut()
            .expect("a running server")
            .try_wait()
            .expect("check the server")
        {
            let mut stderr = String::new();
            if let Some(pipe) = server.0.as_mut().expect("a stopped server").stderr.as_mut() {
                pipe.read_to_string(&mut stderr)
                    .expect("read the stopped server error output");
            }
            panic!("tit serve stopped early with {status}: {stderr}");
        }
        assert!(
            Instant::now() < deadline,
            "listener {address} did not start"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn http_get(address: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address).expect("connect to the HTTP server");
    let timeout = Some(Duration::from_secs(10));
    stream
        .set_read_timeout(timeout)
        .expect("set the HTTP read timeout");
    stream
        .set_write_timeout(timeout)
        .expect("set the HTTP write timeout");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .expect("write an HTTP request");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read an HTTP response");
    response
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn terminate(&mut self) {
        let mut child = self.0.take().expect("the server process is active");
        let signal = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .output()
            .expect("send SIGTERM to the tit server");
        assert!(signal.status.success(), "cannot send SIGTERM");
        let status = child.wait().expect("wait for the tit server");
        assert!(status.success(), "tit serve did not stop cleanly: {status}");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            child.kill().expect("stop the tit server");
            child.wait().expect("wait for the tit server");
        }
    }
}
