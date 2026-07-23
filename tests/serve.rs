#[allow(
    dead_code,
    reason = "the server test uses only part of the shared test support"
)]
mod support;

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use support::{create_ssh_key_fixture, free_address};
use tempfile::TempDir;

#[test]
fn serves_an_imported_repository_through_http_and_ssh() {
    let instance = TempDir::new().expect("create an instance directory");
    let http = free_address();
    let ssh = free_address();
    let config = instance.path().join("config.toml");
    fs::write(
        &config,
        format!(
            "version = 1\npublic_url = \"http://{http}/\"\n\n[http]\nlisten = \"{http}\"\n\n[ssh]\nlisten = \"{ssh}\"\npublic_host = \"127.0.0.1\"\npublic_port = {}\n",
            ssh.port()
        ),
    )
    .expect("write the server configuration");
    let private_key = instance.path().join("administrator");
    create_ssh_key_fixture(&private_key);
    let public_key = fs::read_to_string(private_key.with_extension("pub"))
        .expect("read the administrator public key");
    command(
        instance.path(),
        [
            "--config",
            config.to_str().expect("a UTF-8 configuration path"),
            "setup",
            "admin",
            "alice",
            public_key.trim(),
        ],
    );

    let source = create_source_repository(instance.path());
    command(
        instance.path(),
        [
            "--config",
            config.to_str().expect("a UTF-8 configuration path"),
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
    let control_socket = instance.path().join("control.sock");
    assert_eq!(
        fs::symlink_metadata(&control_socket)
            .expect("inspect the control socket")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let invitation_output = Command::new(env!("CARGO_BIN_EXE_tit"))
        .args([
            "--config",
            config.to_str().expect("a UTF-8 configuration path"),
            "invite-code",
        ])
        .output()
        .expect("request an invitation");
    assert!(invitation_output.status.success());
    let invitation = String::from_utf8(invitation_output.stdout)
        .expect("read the invitation output")
        .trim()
        .strip_prefix("Signup code: ")
        .expect("read the invitation code")
        .to_owned();
    let member_key = instance.path().join("member");
    create_ssh_key_fixture(&member_key);
    let member_public =
        fs::read_to_string(member_key.with_extension("pub")).expect("read the member public key");
    let signup = http_form(
        http,
        "/signup",
        &[
            ("invitation", invitation.as_str()),
            ("username", "bob"),
            ("public-key", member_public.trim()),
        ],
    );
    assert!(signup.starts_with("HTTP/1.1 200"), "{signup}");
    let recovery = between(&signup, "<pre><code>", "</code></pre>");
    assert!(recovery.starts_with("tit-recovery-v1:"));

    let summary = http_get(http, "/alice/example");
    assert!(summary.starts_with("HTTP/1.1 200"));
    assert!(summary.contains("serve fixture"));

    let http_clone = instance.path().join("http-clone");
    command(
        instance.path(),
        [
            "clone",
            "-q",
            &format!("http://{http}/alice/example.git"),
            http_clone.to_str().expect("a UTF-8 HTTP clone path"),
        ],
    );
    assert_eq!(
        fs::read(http_clone.join("README.md")).expect("read the HTTP clone"),
        b"serve fixture\n"
    );

    assert!(ssh_clone_succeeds(
        ssh,
        &member_key,
        &instance.path().join("member-clone")
    ));

    let replacement_key = instance.path().join("replacement");
    create_ssh_key_fixture(&replacement_key);
    let replacement_public = fs::read_to_string(replacement_key.with_extension("pub"))
        .expect("read the replacement public key");
    let recovered = http_form(
        http,
        "/recover",
        &[
            ("recovery", recovery),
            ("username", "bob"),
            ("public-key", replacement_public.trim()),
        ],
    );
    assert!(recovered.starts_with("HTTP/1.1 200"), "{recovered}");
    assert!(!ssh_clone_succeeds(
        ssh,
        &member_key,
        &instance.path().join("revoked-clone")
    ));
    assert!(ssh_clone_succeeds(
        ssh,
        &replacement_key,
        &instance.path().join("replacement-clone")
    ));

    let ssh_clone = instance.path().join("ssh-clone");
    let ssh_command = format!(
        "ssh -F /dev/null -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
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
        .expect("clone through the tit SSH server");
    assert!(
        output.status.success(),
        "SSH clone failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(ssh_clone.join("README.md")).expect("read the SSH clone"),
        b"serve fixture\n"
    );

    let locked = Command::new(env!("CARGO_BIN_EXE_tit"))
        .args([
            "--config",
            config.to_str().expect("a UTF-8 configuration path"),
            "admin",
            "repository",
            "inspect",
            "alice",
            "example",
        ])
        .output()
        .expect("run an offline command while the server owns the instance");
    assert_eq!(locked.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&locked.stderr).contains("owns the instance lock"));

    server.terminate();
    assert!(!control_socket.exists());
    let host_key = fs::read(instance.path().join("ssh_host_ed25519_key"))
        .expect("read the generated SSH host key");
    assert_eq!(
        fs::metadata(instance.path().join("ssh_host_ed25519_key"))
            .expect("inspect the generated SSH host key")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut restarted = spawn_server(&config);
    wait_for_listener(http, &mut restarted);
    wait_for_listener(ssh, &mut restarted);
    assert_eq!(
        fs::read(instance.path().join("ssh_host_ed25519_key"))
            .expect("read the reused SSH host key"),
        host_key
    );
    restarted.terminate();
}

fn spawn_server(config: &Path) -> ChildGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_tit"))
        .args([
            "--config",
            config.to_str().expect("a UTF-8 configuration path"),
            "serve",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the tit server");
    ChildGuard(Some(child))
}

fn create_source_repository(parent: &Path) -> std::path::PathBuf {
    let worktree = parent.join("source-worktree");
    command(
        parent,
        [
            "init",
            "-q",
            "-b",
            "main",
            worktree.to_str().expect("a UTF-8 worktree path"),
        ],
    );
    fs::write(worktree.join("README.md"), b"serve fixture\n").expect("write source content");
    command(&worktree, ["add", "."]);
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
    assert!(output.status.success(), "Git commit failed");
    let bare = parent.join("source.git");
    command(
        parent,
        [
            "clone",
            "-q",
            "--bare",
            worktree.to_str().expect("a UTF-8 worktree path"),
            bare.to_str().expect("a UTF-8 bare path"),
        ],
    );
    bare
}

fn command<const N: usize>(directory: &Path, arguments: [&str; N]) {
    let executable = if matches!(arguments.first(), Some(&"--config")) {
        env!("CARGO_BIN_EXE_tit")
    } else {
        "git"
    };
    let output = Command::new(executable)
        .args(arguments)
        .current_dir(directory)
        .output()
        .expect("run a fixture command");
    assert!(
        output.status.success(),
        "fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
            panic!("tit serve stopped early with {status}");
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

fn http_form(address: SocketAddr, path: &str, fields: &[(&str, &str)]) -> String {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish();
    let mut stream = TcpStream::connect(address).expect("connect to the HTTP server");
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write an HTTP form");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read an HTTP response");
    response
}

fn between<'a>(value: &'a str, start: &str, end: &str) -> &'a str {
    value
        .split_once(start)
        .and_then(|(_, tail)| tail.split_once(end))
        .map(|(value, _)| value)
        .expect("find the response value")
}

fn ssh_clone_succeeds(address: SocketAddr, private_key: &Path, target: &Path) -> bool {
    let ssh_command = format!(
        "ssh -F /dev/null -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        private_key.display()
    );
    Command::new("git")
        .args([
            "clone",
            "-q",
            &format!(
                "ssh://ignored@127.0.0.1:{}/alice/example.git",
                address.port()
            ),
        ])
        .arg(target)
        .env("GIT_SSH_COMMAND", ssh_command)
        .output()
        .expect("clone through the tit SSH server")
        .status
        .success()
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn terminate(&mut self) {
        if let Some(mut child) = self.0.take() {
            let signal = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .output()
                .expect("send SIGTERM to the tit server");
            assert!(signal.status.success(), "cannot send SIGTERM");
            let status = child.wait().expect("wait for the tit server");
            assert!(status.success(), "tit serve did not stop cleanly: {status}");
        }
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.0.take() {
            child.kill().expect("stop the tit server");
            child.wait().expect("wait for the tit server");
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}
