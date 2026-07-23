#[allow(
    dead_code,
    reason = "the server test uses only part of the shared test support"
)]
mod support;

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use support::{create_ssh_key_fixture, free_address};
use tempfile::TempDir;

static SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn server_test_lock() -> MutexGuard<'static, ()> {
    SERVER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn serves_an_imported_repository_through_http_and_ssh() {
    let _server_test = server_test_lock();
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
    let health = http_get(http, "/healthz");
    assert!(health.starts_with("HTTP/1.1 200"));
    assert!(health.ends_with("\r\n\r\nready\n"));

    let backup_directory = TempDir::new().expect("create a backup directory");
    let backup = backup_directory.path().join("instance.tar");
    let backup_output = Command::new(tit_binary())
        .args([
            "--config",
            config.to_str().expect("a UTF-8 configuration path"),
            "backup",
            backup.to_str().expect("a UTF-8 backup path"),
        ])
        .output()
        .expect("request an online backup");
    assert!(
        backup_output.status.success(),
        "online backup failed: {}",
        String::from_utf8_lossy(&backup_output.stderr)
    );
    assert!(String::from_utf8_lossy(&backup_output.stdout).contains("contains credentials"));
    assert_eq!(
        fs::metadata(&backup)
            .expect("inspect the backup")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let restored = TempDir::new().expect("create a restore target");
    fs::set_permissions(restored.path(), fs::Permissions::from_mode(0o700))
        .expect("make the restore target private");
    let restore_output = Command::new(tit_binary())
        .args([
            "restore",
            backup.to_str().expect("a UTF-8 backup path"),
            restored.path().to_str().expect("a UTF-8 restore path"),
        ])
        .output()
        .expect("restore the online backup");
    assert!(
        restore_output.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&restore_output.stderr)
    );
    assert!(String::from_utf8_lossy(&restore_output.stdout).contains("is not active"));
    let restored_database = rusqlite::Connection::open(restored.path().join("tit.sqlite3"))
        .expect("open the restored database");
    let restored_repository: String = restored_database
        .query_row(
            "SELECT id FROM repository WHERE slug = 'example'",
            [],
            |row| row.get(0),
        )
        .expect("read the restored repository");
    drop(restored_database);
    let restored_readme = Command::new("git")
        .args(["--git-dir"])
        .arg(
            restored
                .path()
                .join("repositories")
                .join(format!("{restored_repository}.git")),
        )
        .args(["show", "main:README.md"])
        .output()
        .expect("read the restored Git repository");
    assert!(restored_readme.status.success());
    assert_eq!(restored_readme.stdout, b"serve fixture\n");

    let second = Command::new(tit_binary())
        .args([
            "--config",
            config.to_str().expect("a UTF-8 configuration path"),
            "serve",
        ])
        .output()
        .expect("start a second tit server");
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("owns the instance lock"));

    let control_socket = instance.path().join("control.sock");
    assert_eq!(
        fs::symlink_metadata(&control_socket)
            .expect("inspect the control socket")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let anonymous_home = http_get(http, "/");
    assert!(
        anonymous_home.contains("Recently updated public repositories"),
        "anonymous home response:\n{anonymous_home}"
    );
    assert!(anonymous_home.contains(">alice/example</a>"));
    assert!(anonymous_home.contains("<a href=\"/signup\">Create account</a>"));
    assert!(anonymous_home.contains("<a href=\"/recover\">Recover account</a>"));
    assert!(anonymous_home.contains("<a href=\"/login\">Log in</a>"));
    assert!(!anonymous_home.contains("<a href=\"/account\">Account</a>"));

    let login_challenge = http_form(
        http,
        "/login",
        &[("username", "alice"), ("public-key", public_key.trim())],
    );
    assert!(login_challenge.starts_with("HTTP/1.1 200"));
    let challenge = between(
        &login_challenge,
        "<textarea id=\"challenge-display\" readonly rows=\"10\">",
        "</textarea>",
    );
    let signature = sign_challenge(instance.path(), &private_key, challenge);
    let browser_challenge = challenge.replace('\n', "\r\n");
    let browser_signature = signature.replace('\n', "\r\n");
    let login_csrf_cookies = response_cookies(&login_challenge);
    let login_csrf = cookie_value(&login_csrf_cookies, "tit-login-csrf");
    let rejected_login = http_form_with_headers(
        http,
        "/login/verify",
        &[
            ("username", "alice"),
            ("public-key", public_key.trim()),
            ("challenge", &browser_challenge),
            ("signature", &browser_signature),
            ("login-csrf", &"0".repeat(64)),
        ],
        &[("Cookie", &login_csrf_cookies)],
    );
    assert!(rejected_login.starts_with("HTTP/1.1 400"));
    let rejected_login_id = response_header(&rejected_login, "x-request-id").to_owned();
    let login = http_form_with_headers(
        http,
        "/login/verify",
        &[
            ("username", "alice"),
            ("public-key", public_key.trim()),
            ("challenge", &browser_challenge),
            ("signature", &browser_signature),
            ("login-csrf", login_csrf),
        ],
        &[("Cookie", &login_csrf_cookies)],
    );
    assert!(login.starts_with("HTTP/1.1 303"), "{login}");
    let login_id = response_header(&login, "x-request-id").to_owned();
    let cookies = response_cookies(&login);
    let account = http_get_with_headers(http, "/account", &[("Cookie", &cookies)]);
    assert!(account.starts_with("HTTP/1.1 200"));
    assert!(account.contains("<dd>alice</dd>"));
    assert!(account.contains("<a href=\"/account\">Account</a>"));
    assert!(account.contains("<a href=\"/logout\">Log out</a>"));
    assert!(!account.contains("<a href=\"/login\">Log in</a>"));
    assert!(!account.contains("<a href=\"/signup\">Create account</a>"));
    assert!(!account.contains("<a href=\"/recover\">Recover account</a>"));
    assert!(account.contains("action=\"/account/repositories\""));
    for path in ["/login", "/signup", "/recover"] {
        let response = http_get_with_headers(http, path, &[("Cookie", &cookies)]);
        assert!(response.starts_with("HTTP/1.1 303"));
        assert_eq!(response_header(&response, "location"), "/account");
    }
    let signed_in_home = http_get_with_headers(http, "/", &[("Cookie", &cookies)]);
    assert!(signed_in_home.contains("<h1>alice</h1>"));
    assert!(signed_in_home.contains("<h2>Your repositories</h2>"));
    assert!(signed_in_home.contains(">alice/example</a>"));
    assert!(signed_in_home.contains("<a href=\"/account\">Account</a>"));
    assert!(signed_in_home.contains("<a href=\"/logout\">Log out</a>"));
    assert!(!signed_in_home.contains("<a href=\"/signup\">Create account</a>"));
    assert!(!signed_in_home.contains("<a href=\"/recover\">Recover account</a>"));
    assert!(!signed_in_home.contains("<a href=\"/login\">Log in</a>"));
    let csrf = cookie_value(&cookies, "tit-csrf");
    let logout_page = http_get_with_headers(http, "/logout", &[("Cookie", &cookies)]);
    assert!(logout_page.starts_with("HTTP/1.1 200"));
    assert!(logout_page.contains("<form method=\"post\" action=\"/logout\">"));
    assert!(logout_page.contains(&format!("name=\"csrf\" value=\"{csrf}\"")));
    let rejected_repository = http_form_with_headers(
        http,
        "/account/repositories",
        &[
            ("csrf", &"0".repeat(64)),
            ("name", "web-created"),
            ("object-format", "sha1"),
        ],
        &[("Cookie", &cookies)],
    );
    assert!(rejected_repository.starts_with("HTTP/1.1 403"));
    let created_repository = http_form_with_headers(
        http,
        "/account/repositories",
        &[
            ("csrf", csrf),
            ("name", "web-created"),
            ("object-format", "sha256"),
        ],
        &[("Cookie", &cookies)],
    );
    assert!(created_repository.starts_with("HTTP/1.1 303"));
    assert_eq!(
        response_header(&created_repository, "location"),
        "/alice/web-created"
    );
    let web_create_id = response_header(&created_repository, "x-request-id").to_owned();
    assert!(http_get(http, "/alice/web-created").starts_with("HTTP/1.1 200"));
    let rejected_logout = http_form_with_headers(
        http,
        "/logout",
        &[("csrf", &"0".repeat(64))],
        &[("Cookie", &cookies)],
    );
    assert!(rejected_logout.starts_with("HTTP/1.1 403"));
    let logout =
        http_form_with_headers(http, "/logout", &[("csrf", csrf)], &[("Cookie", &cookies)]);
    assert!(logout.starts_with("HTTP/1.1 303"));
    let ended = http_get_with_headers(http, "/account", &[("Cookie", &cookies)]);
    assert!(ended.starts_with("HTTP/1.1 303"));

    let upload_challenge_page = http_form(
        http,
        "/login",
        &[("username", "alice"), ("public-key", public_key.trim())],
    );
    let upload_challenge = between(
        &upload_challenge_page,
        "<textarea id=\"challenge-display\" readonly rows=\"10\">",
        "</textarea>",
    );
    let upload_signature = sign_challenge(instance.path(), &private_key, upload_challenge);
    let browser_upload_challenge = upload_challenge.replace('\n', "\r\n");
    let upload_csrf_cookies = response_cookies(&upload_challenge_page);
    let upload_csrf = cookie_value(&upload_csrf_cookies, "tit-login-csrf");
    let wrong_upload_type = http_form_with_headers(
        http,
        "/login/verify-file",
        &[("signature-file", &upload_signature)],
        &[("Cookie", &upload_csrf_cookies)],
    );
    assert!(wrong_upload_type.starts_with("HTTP/1.1 400"));
    let malformed_upload = http_body(
        http,
        "/login/verify-file",
        "multipart/form-data; boundary=tit-broken-boundary",
        "--tit-broken-boundary\r\ninvalid",
        &[("Cookie", &upload_csrf_cookies)],
    );
    assert!(malformed_upload.starts_with("HTTP/1.1 400"));
    let uploaded = http_multipart(
        http,
        "/login/verify-file",
        &[
            ("username", "alice"),
            ("public-key", public_key.trim()),
            ("challenge", &browser_upload_challenge),
            ("signature-file", &upload_signature),
            ("login-csrf", upload_csrf),
        ],
        &[("Cookie", &upload_csrf_cookies)],
    );
    assert!(uploaded.starts_with("HTTP/1.1 303"), "{uploaded}");
    let private_cookies = response_cookies(&uploaded);
    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the repository database");
    database
        .execute(
            "UPDATE repository SET visibility = 'private' WHERE slug = 'example'",
            [],
        )
        .expect("make the repository private");
    assert!(http_get(http, "/alice/example").starts_with("HTTP/1.1 404"));
    let private_summary =
        http_get_with_headers(http, "/alice/example", &[("Cookie", &private_cookies)]);
    assert!(private_summary.starts_with("HTTP/1.1 200"));
    let private_feed = http_get_with_headers(
        http,
        "/alice/example/atom.xml",
        &[("Cookie", &private_cookies)],
    );
    assert!(private_feed.starts_with("HTTP/1.1 200"));
    assert!(private_feed.contains("cache-control: private, no-store"));
    database
        .execute(
            "UPDATE repository SET visibility = 'public' WHERE slug = 'example'",
            [],
        )
        .expect("make the repository public");
    drop(database);

    let invitation_output = Command::new(tit_binary())
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
    let recovery_id = response_header(&recovered, "x-request-id").to_owned();
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

    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the audit database");
    let mut statement = database
        .prepare(
            "SELECT action, actor, target, outcome, correlation_id
             FROM audit_event ORDER BY id",
        )
        .expect("prepare the audit query");
    let audits = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .expect("query audit history")
        .collect::<Result<Vec<_>, _>>()
        .expect("read audit history");
    assert!(audits.iter().any(|event| {
        event.0 == "login" && event.3 == "failure" && event.4 == rejected_login_id
    }));
    assert!(
        audits
            .iter()
            .any(|event| event.0 == "login" && event.3 == "success" && event.4 == login_id)
    );
    assert!(audits.iter().any(|event| {
        event.0 == "account.recover" && event.3 == "success" && event.4 == recovery_id
    }));
    assert!(audits.iter().any(|event| {
        event.0 == "repository.create"
            && event.1 == "alice"
            && event.2 == "alice/web-created"
            && event.3 == "success"
            && event.4 == web_create_id
    }));
    for event in &audits {
        let visible = format!(
            "{} {} {} {} {}",
            event.0, event.1, event.2, event.3, event.4
        );
        assert!(!visible.contains(recovery));
        assert!(!visible.contains(challenge));
        assert!(!visible.contains(&signature));
    }
    drop(statement);
    drop(database);

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

    let locked = Command::new(tit_binary())
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

    let metrics = http_get(http, "/metrics");
    assert!(metrics.starts_with("HTTP/1.1 200"));
    assert!(metrics.contains("tit_http_requests_total "));
    assert!(metrics.contains("tit_http_requests_in_flight 1"));
    assert!(metrics.contains("tit_ssh_connections_total "));
    assert!(metrics.contains("tit_ssh_operations_total "));

    let authorization_secret = "Bearer tit-secret-authorization";
    let cookie_secret = "tit-session=tit-secret-cookie";
    let feed_secret = "tit-secret-feed-token";
    let _ = http_get_with_headers(
        http,
        "/",
        &[
            ("Authorization", authorization_secret),
            ("Cookie", cookie_secret),
        ],
    );
    let _ = http_get(http, &format!("/feeds/{feed_secret}.atom"));

    let logs = server.terminate_capture();
    let logs = String::from_utf8(logs).expect("read structured server logs");
    assert!(!logs.contains(authorization_secret));
    assert!(!logs.contains(cookie_secret));
    assert!(!logs.contains(feed_secret));
    for secret in [
        recovery,
        challenge,
        signature.as_str(),
        invitation.trim(),
        private_cookies.as_str(),
        upload_signature.as_str(),
    ] {
        assert!(!logs.contains(secret));
    }
    let events: Vec<serde_json::Value> = logs
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse a structured server log"))
        .collect();
    assert!(events.iter().any(|event| {
        event["event"] == "http.request"
            && event["request_id"]
                .as_str()
                .is_some_and(|request_id| request_id.len() == 32)
    }));
    assert!(events.iter().any(|event| {
        event["event"] == "ssh.operation"
            && event["operation_id"]
                .as_str()
                .is_some_and(|operation_id| operation_id.len() == 32)
    }));
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "server.shutdown" && event["outcome"] == "completed")
    );

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

#[test]
fn keeps_private_git_hidden_from_http_but_allows_its_owner_over_ssh() {
    let _server_test = server_test_lock();
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
    let config_text = config.to_str().expect("a UTF-8 configuration path");
    command(
        instance.path(),
        [
            "--config",
            config_text,
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
            config_text,
            "admin",
            "repository",
            "import",
            "alice",
            "private",
            source.to_str().expect("a UTF-8 source path"),
        ],
    );
    command(
        instance.path(),
        [
            "--config",
            config_text,
            "admin",
            "repository",
            "visibility",
            "alice",
            "private",
            "private",
        ],
    );
    let mut server = spawn_server(&config);
    wait_for_listener(http, &mut server);
    wait_for_listener(ssh, &mut server);
    let discovery = http_get(http, "/alice/private.git/info/refs?service=git-upload-pack");
    assert!(discovery.starts_with("HTTP/1.1 404"), "{discovery}");
    let home = http_get(http, "/");
    assert!(home.starts_with("HTTP/1.1 200"));
    assert!(!home.contains("/alice/private"));
    for route in [
        "/alice/private",
        "/alice/private/refs",
        "/alice/private/atom.xml",
        "/alice/private/rss.xml",
        "/alice/private/search?q=serve&ref=HEAD",
        "/alice/private/commit/main",
        "/alice/private/diff/main/main",
        "/alice/private/tree/main",
        "/alice/private/tree/main/nested",
        "/alice/private/blob/main/README.md",
        "/alice/private/raw/main/README.md",
        "/alice/private/blame/main/README.md",
        "/alice/private/archive/main.tar",
    ] {
        let response = http_get(http, route);
        assert!(
            response.starts_with("HTTP/1.1 404"),
            "route leaked: {route}"
        );
        assert!(!response.contains("serve fixture"), "route leaked: {route}");
    }

    let ssh_command = format!(
        "ssh -F /dev/null -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        private_key.display()
    );
    let ssh_discovery = Command::new("git")
        .args([
            "ls-remote",
            &format!("ssh://ignored@127.0.0.1:{}/alice/private.git", ssh.port()),
        ])
        .env("GIT_SSH_COMMAND", ssh_command)
        .output()
        .expect("query the private repository through SSH");
    assert!(ssh_discovery.status.success());

    let unknown_key = instance.path().join("unknown");
    create_ssh_key_fixture(&unknown_key);
    assert!(!ssh_clone_repository_succeeds(
        ssh,
        &unknown_key,
        "alice",
        "private",
        &instance.path().join("unknown-clone")
    ));
    server.terminate();
}

#[test]
fn creates_owned_repositories_with_stable_ssh_command_output() {
    let _server_test = server_test_lock();
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
    let config_text = config.to_str().expect("a UTF-8 configuration path");
    command(
        instance.path(),
        [
            "--config",
            config_text,
            "setup",
            "admin",
            "alice",
            public_key.trim(),
        ],
    );
    let member_key = provision_account(instance.path(), "bob", "active", false);

    let mut server = spawn_server(&config);
    wait_for_listener(http, &mut server);
    wait_for_listener(ssh, &mut server);

    let human = ssh_exec(ssh, &member_key, &["repo", "create", "example"]);
    assert!(human.status.success());
    assert_eq!(
        String::from_utf8(human.stdout).expect("read human command output"),
        "Created repository bob/example.\nObject format: sha1\n"
    );
    assert!(human.stderr.is_empty());
    assert!(ssh_clone_repository_succeeds(
        ssh,
        &member_key,
        "bob",
        "example",
        &instance.path().join("created-clone")
    ));
    let created_clone = instance.path().join("created-clone");
    command(&created_clone, ["symbolic-ref", "HEAD", "refs/heads/main"]);
    fs::write(created_clone.join("README.md"), b"base\n").expect("write pull-request base");
    git_commit(&created_clone, "create main");
    assert!(git_push(&member_key, &created_clone, &["main"]).success());
    command(&created_clone, ["switch", "-q", "-c", "feature"]);
    fs::write(created_clone.join("feature.txt"), b"feature\n").expect("write pull-request feature");
    git_commit(&created_clone, "create feature");
    assert!(git_push(&member_key, &created_clone, &["feature"]).success());
    let base = git_revision(&created_clone, "main");
    let head = git_revision(&created_clone, "feature");
    let pull_request_database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the pull-request command database");
    let repository_id: String = pull_request_database
        .query_row(
            "SELECT id FROM repository WHERE slug = 'example'",
            [],
            |row| row.get(0),
        )
        .expect("read the pull-request repository ID");
    let bare = instance
        .path()
        .join("repositories")
        .join(format!("{repository_id}.git"));
    command(
        instance.path(),
        [
            "--git-dir",
            bare.to_str().expect("a UTF-8 bare path"),
            "update-ref",
            "refs/pull/1/head",
            &head,
        ],
    );
    pull_request_database
        .execute(
            "INSERT INTO pull_request
             (id, repository_id, number, title, body, state, author_account_id,
              base_ref, head_ref, base_object_id, head_object_id, created_at, updated_at)
             SELECT '11111111111111111111111111111111', ?1, 1, 'Feature', '', 'open',
                    account.id, 'refs/heads/main', 'refs/heads/feature', ?2, ?3, 10, 10
             FROM account WHERE username = 'bob'",
            rusqlite::params![repository_id, base, head],
        )
        .expect("create a pull-request command fixture");
    pull_request_database
        .execute(
            "INSERT INTO pull_request_revision
             (id, pull_request_id, number, author_account_id, base_object_id,
              head_object_id, created_at)
             SELECT '22222222222222222222222222222222',
                    '11111111111111111111111111111111', 1, account.id, ?1, ?2, 10
             FROM account WHERE username = 'bob'",
            rusqlite::params![base, head],
        )
        .expect("create a pull-request revision fixture");
    drop(pull_request_database);

    let human_checkout = ssh_exec(ssh, &member_key, &["pr", "checkout", "bob/example", "1"]);
    assert!(human_checkout.status.success());
    assert_eq!(
        String::from_utf8(human_checkout.stdout).expect("read human checkout output"),
        "git fetch origin refs/pull/1/head:refs/heads/pr-1\ngit checkout pr-1\n"
    );
    assert!(human_checkout.stderr.is_empty());
    let machine_checkout = ssh_exec(
        ssh,
        &member_key,
        &["pr", "checkout", "bob/example", "1", "--output", "json"],
    );
    assert!(machine_checkout.status.success());
    let machine_checkout: serde_json::Value =
        serde_json::from_slice(&machine_checkout.stdout).expect("parse machine checkout output");
    assert_eq!(machine_checkout["version"], 1);
    assert_eq!(machine_checkout["status"], "success");
    assert_eq!(machine_checkout["repository"]["owner"], "bob");
    assert_eq!(machine_checkout["repository"]["name"], "example");
    assert_eq!(machine_checkout["pull_request"]["number"], 1);
    assert_eq!(machine_checkout["pull_request"]["ref"], "refs/pull/1/head");
    assert_eq!(
        machine_checkout["commands"]["fetch"],
        "git fetch origin refs/pull/1/head:refs/heads/pr-1"
    );
    let checkout_clone = instance.path().join("pull-request-checkout");
    assert!(ssh_clone_repository_succeeds(
        ssh,
        &member_key,
        "bob",
        "example",
        &checkout_clone
    ));
    assert!(
        git_fetch_ref(
            &member_key,
            &checkout_clone,
            "refs/pull/1/head:refs/heads/pr-1"
        )
        .success()
    );
    command(&checkout_clone, ["checkout", "-q", "pr-1"]);
    assert_eq!(git_revision(&checkout_clone, "HEAD"), head);

    let machine = ssh_exec(
        ssh,
        &private_key,
        &[
            "repo",
            "create",
            "hash-agile",
            "--object-format",
            "sha256",
            "--output",
            "json",
        ],
    );
    assert!(machine.status.success());
    assert_eq!(
        String::from_utf8(machine.stdout).expect("read machine command output"),
        "{\"version\":1,\"status\":\"success\",\"repository\":{\"owner\":\"alice\",\"name\":\"hash-agile\",\"object_format\":\"sha256\"}}\n"
    );
    assert!(machine.stderr.is_empty());

    let created_issue = ssh_exec_with_input(
        ssh,
        &member_key,
        &["issue", "create", "bob/example"],
        b"First issue\nBody with **Markdown**.\n",
    );
    assert!(created_issue.status.success());
    assert_eq!(
        String::from_utf8(created_issue.stdout).expect("read issue create output"),
        "Created issue bob/example#1.\n"
    );
    assert!(created_issue.stderr.is_empty());
    let human_issues = ssh_exec(ssh, &member_key, &["issue", "list", "bob/example"]);
    assert!(human_issues.status.success());
    assert_eq!(
        String::from_utf8(human_issues.stdout).expect("read human issue list"),
        "#1 open First issue\n"
    );
    let machine_issues = ssh_exec(
        ssh,
        &member_key,
        &["issue", "list", "bob/example", "--output", "json"],
    );
    assert!(machine_issues.status.success());
    let machine_issues: serde_json::Value =
        serde_json::from_slice(&machine_issues.stdout).expect("parse machine issue list");
    assert_eq!(machine_issues["version"], 1);
    assert_eq!(machine_issues["status"], "success");
    assert_eq!(machine_issues["repository"]["owner"], "bob");
    assert_eq!(machine_issues["repository"]["name"], "example");
    assert_eq!(machine_issues["issues"][0]["number"], 1);
    assert_eq!(machine_issues["issues"][0]["title"], "First issue");

    let access_database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the issue access database");
    access_database
        .execute_batch("UPDATE repository SET visibility = 'private' WHERE slug = 'example';")
        .expect("make the issue repository private");
    let hidden = ssh_exec(
        ssh,
        &private_key,
        &["issue", "list", "bob/example", "--output", "json"],
    );
    assert!(!hidden.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&hidden.stdout)
            .expect("parse hidden issue error")["error"]["code"],
        "repository-unavailable"
    );
    let hidden_checkout = ssh_exec(
        ssh,
        &private_key,
        &["pr", "checkout", "bob/example", "1", "--output", "json"],
    );
    assert!(!hidden_checkout.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&hidden_checkout.stdout)
            .expect("parse hidden pull-request error")["error"]["code"],
        "pull-request-unavailable"
    );
    access_database
        .execute(
            "INSERT INTO repository_collaborator
                 (repository_id, account_id, role, created_at)
             SELECT repository.id, account.id, 'reader', 10
             FROM repository, account
             WHERE repository.slug = 'example' AND account.username = 'alice'",
            [],
        )
        .expect("give the administrator reader access");
    drop(access_database);
    let reader_create = ssh_exec_with_input(
        ssh,
        &private_key,
        &["issue", "create", "bob/example", "--output", "json"],
        b"Reader issue\nCreated through the shared service.",
    );
    assert!(reader_create.status.success());
    let reader_create: serde_json::Value =
        serde_json::from_slice(&reader_create.stdout).expect("parse machine issue create");
    assert_eq!(reader_create["version"], 1);
    assert_eq!(reader_create["status"], "success");
    assert_eq!(reader_create["issue"]["number"], 2);
    assert_eq!(reader_create["issue"]["author"], "alice");

    let invalid_issue = ssh_exec_with_input(
        ssh,
        &private_key,
        &["issue", "create", "bob/example", "--output", "json"],
        b"\nbody without a title",
    );
    assert!(!invalid_issue.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invalid_issue.stdout)
            .expect("parse invalid issue input")["error"]["code"],
        "invalid-input"
    );

    let duplicate = ssh_exec(
        ssh,
        &member_key,
        &["repo", "create", "example", "--output", "json"],
    );
    assert!(!duplicate.status.success());
    assert_eq!(
        String::from_utf8(duplicate.stdout).expect("read machine error output"),
        "{\"version\":1,\"status\":\"error\",\"error\":{\"code\":\"repository-exists\"}}\n"
    );
    assert!(duplicate.stderr.is_empty());

    let invalid = ssh_exec(ssh, &member_key, &["repo", "create", "../bad"]);
    assert!(!invalid.status.success());
    assert!(invalid.stdout.is_empty());
    assert_eq!(
        String::from_utf8(invalid.stderr).expect("read human error output"),
        "tit: The repository name is not valid.\n"
    );
    let malformed = ssh_exec(ssh, &member_key, &["repo", "create", "--output", "json"]);
    assert!(!malformed.status.success());
    assert_eq!(
        String::from_utf8(malformed.stdout).expect("read invalid command output"),
        "{\"version\":1,\"status\":\"error\",\"error\":{\"code\":\"invalid-command\"}}\n"
    );
    assert!(malformed.stderr.is_empty());

    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the account database");
    database
        .execute(
            "UPDATE account SET state = 'suspended' WHERE username = 'bob'",
            [],
        )
        .expect("suspend the command account");
    drop(database);
    let suspended = ssh_exec(
        ssh,
        &member_key,
        &["repo", "create", "blocked", "--output", "json"],
    );
    assert!(!suspended.status.success());
    assert_eq!(
        String::from_utf8(suspended.stdout).expect("read suspended account output"),
        "{\"version\":1,\"status\":\"error\",\"error\":{\"code\":\"account-unavailable\"}}\n"
    );
    assert!(suspended.stderr.is_empty());
    let suspended_issues = ssh_exec(
        ssh,
        &member_key,
        &["issue", "list", "bob/example", "--output", "json"],
    );
    assert!(!suspended_issues.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&suspended_issues.stdout)
            .expect("parse suspended issue output")["error"]["code"],
        "repository-unavailable"
    );
    server.terminate();

    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the repository database");
    let repositories: Vec<(String, String, String)> = database
        .prepare(
            "SELECT account.username, repository.slug, repository.object_format
             FROM repository JOIN account ON account.id = repository.owner_account_id
             ORDER BY repository.slug",
        )
        .expect("prepare the repository query")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query created repositories")
        .collect::<Result<_, _>>()
        .expect("read created repositories");
    assert_eq!(
        repositories,
        vec![
            ("bob".to_owned(), "example".to_owned(), "sha1".to_owned()),
            (
                "alice".to_owned(),
                "hash-agile".to_owned(),
                "sha256".to_owned()
            ),
        ]
    );
    let issues: Vec<(i64, String, String, String)> = database
        .prepare(
            "SELECT issue.number, issue.title, issue.body, account.username
             FROM issue JOIN account ON account.id = issue.author_account_id
             ORDER BY issue.number",
        )
        .expect("prepare the issue query")
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("query created issues")
        .collect::<Result<_, _>>()
        .expect("read created issues");
    assert_eq!(
        issues,
        vec![
            (
                1,
                "First issue".to_owned(),
                "Body with **Markdown**.\n".to_owned(),
                "bob".to_owned(),
            ),
            (
                2,
                "Reader issue".to_owned(),
                "Created through the shared service.".to_owned(),
                "alice".to_owned(),
            ),
        ]
    );
    let issue_events: i64 = database
        .query_row(
            "SELECT count(*) FROM repository_event WHERE kind = 'issue-created'",
            [],
            |row| row.get(0),
        )
        .expect("count issue create events");
    assert_eq!(issue_events, 2);
    let audit: Vec<(String, String)> = database
        .prepare(
            "SELECT target, outcome FROM audit_event
             WHERE action = 'repository.create' AND actor IN ('alice', 'bob')
             ORDER BY id",
        )
        .expect("prepare the repository audit query")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query repository audit events")
        .collect::<Result<_, _>>()
        .expect("read repository audit events");
    assert_eq!(
        audit,
        vec![
            ("bob/example".to_owned(), "success".to_owned()),
            ("alice/hash-agile".to_owned(), "success".to_owned()),
            ("bob/example".to_owned(), "failure".to_owned()),
            ("bob/blocked".to_owned(), "failure".to_owned()),
        ]
    );
}

#[test]
fn enforces_account_roles_and_ref_policy_through_the_production_ssh_server() {
    let _server_test = server_test_lock();
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
    let config_text = config.to_str().expect("a UTF-8 configuration path");
    let owner_key = instance.path().join("owner");
    create_ssh_key_fixture(&owner_key);
    let owner_public =
        fs::read_to_string(owner_key.with_extension("pub")).expect("read the owner public key");
    command(
        instance.path(),
        [
            "--config",
            config_text,
            "setup",
            "admin",
            "alice",
            owner_public.trim(),
        ],
    );

    let source = create_source_repository(instance.path());
    for repository in ["private", "public"] {
        command(
            instance.path(),
            [
                "--config",
                config_text,
                "admin",
                "repository",
                "import",
                "alice",
                repository,
                source.to_str().expect("a UTF-8 source path"),
            ],
        );
    }
    command(
        instance.path(),
        [
            "--config",
            config_text,
            "admin",
            "repository",
            "visibility",
            "alice",
            "private",
            "private",
        ],
    );

    let maintainer_key = provision_account(instance.path(), "maintainer", "active", false);
    let writer_key = provision_account(instance.path(), "writer", "active", false);
    let reader_key = provision_account(instance.path(), "reader", "active", false);
    let outsider_key = provision_account(instance.path(), "outsider", "active", false);
    let suspended_key = provision_account(instance.path(), "suspended", "active", false);
    let revoked_key = provision_account(instance.path(), "revoked", "active", true);
    for (username, role) in [
        ("maintainer", "maintainer"),
        ("writer", "writer"),
        ("reader", "reader"),
        ("suspended", "writer"),
        ("revoked", "writer"),
    ] {
        command(
            instance.path(),
            [
                "--config",
                config_text,
                "admin",
                "repository",
                "collaborator-set",
                "alice",
                "private",
                username,
                role,
            ],
        );
    }
    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the repository database");
    database
        .execute(
            "UPDATE account SET state = 'suspended' WHERE username = 'suspended'",
            [],
        )
        .expect("suspend an account fixture");
    drop(database);

    let mut server = spawn_server(&config);
    wait_for_listener(http, &mut server);
    wait_for_listener(ssh, &mut server);
    for (name, key) in [
        ("owner", &owner_key),
        ("maintainer", &maintainer_key),
        ("writer", &writer_key),
        ("reader", &reader_key),
    ] {
        assert!(ssh_clone_repository_succeeds(
            ssh,
            key,
            "alice",
            "private",
            &instance.path().join(format!("{name}-private"))
        ));
    }
    for (name, key) in [
        ("outsider", &outsider_key),
        ("suspended", &suspended_key),
        ("revoked", &revoked_key),
    ] {
        assert!(!ssh_clone_repository_succeeds(
            ssh,
            key,
            "alice",
            "private",
            &instance.path().join(format!("{name}-private"))
        ));
    }
    assert!(ssh_clone_repository_succeeds(
        ssh,
        &outsider_key,
        "alice",
        "public",
        &instance.path().join("outsider-public")
    ));

    let writer_clone = instance.path().join("writer-private");
    command(&writer_clone, ["switch", "-q", "-c", "topic"]);
    fs::write(writer_clone.join("writer.txt"), b"writer update\n").expect("write a writer change");
    git_commit(&writer_clone, "writer update");
    assert!(git_push(&writer_key, &writer_clone, &["topic"]).success());
    fs::write(writer_clone.join("writer-2.txt"), b"second writer update\n")
        .expect("write a second writer change");
    git_commit(&writer_clone, "second writer update");
    assert!(git_push(&writer_key, &writer_clone, &["topic"]).success());
    assert!(git_push(&writer_key, &writer_clone, &["--delete", "topic"]).success());
    assert!(!git_push(&writer_key, &writer_clone, &["HEAD:main"]).success());
    assert!(!git_push(&writer_key, &writer_clone, &["HEAD:refs/notes/test"]).success());

    let owner_clone = instance.path().join("owner-private");
    fs::write(owner_clone.join("owner.txt"), b"owner update\n").expect("write an owner change");
    git_commit(&owner_clone, "owner update");
    assert!(git_push(&owner_key, &owner_clone, &["main"]).success());
    assert!(!git_push(&owner_key, &owner_clone, &["--delete", "main"]).success());
    command(&owner_clone, ["switch", "-q", "-c", "force-test"]);
    fs::write(owner_clone.join("force.txt"), b"first history\n").expect("write a branch change");
    git_commit(&owner_clone, "first branch history");
    assert!(git_push(&owner_key, &owner_clone, &["force-test"]).success());
    command(&owner_clone, ["reset", "--hard", "HEAD~1"]);
    fs::write(owner_clone.join("force.txt"), b"replacement history\n")
        .expect("write replacement history");
    git_commit(&owner_clone, "replacement branch history");
    let force_result = git_push_output(&owner_key, &owner_clone, &["--force", "force-test"]);
    assert!(!force_result.status.success());
    assert!(String::from_utf8_lossy(&force_result.stderr).contains("non-fast-forward"));

    let reader_clone = instance.path().join("reader-write-private");
    assert!(ssh_clone_repository_succeeds(
        ssh,
        &reader_key,
        "alice",
        "private",
        &reader_clone
    ));
    fs::write(reader_clone.join("reader.txt"), b"reader update\n").expect("write a reader change");
    git_commit(&reader_clone, "reader update");
    assert!(!git_push(&reader_key, &reader_clone, &["main"]).success());

    command(&writer_clone, ["switch", "-q", "main"]);
    fs::write(writer_clone.join("removed-role.txt"), b"removed role\n")
        .expect("write a change before role removal");
    git_commit(&writer_clone, "change before role removal");
    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the repository database");
    database
        .execute(
            "DELETE FROM repository_collaborator
             WHERE account_id = (SELECT id FROM account WHERE username = 'writer')",
            [],
        )
        .expect("remove the writer role");
    drop(database);
    assert!(
        !git_push(
            &writer_key,
            &writer_clone,
            &["HEAD:refs/heads/removed-role"]
        )
        .success()
    );
    server.terminate();
    let database = rusqlite::Connection::open(instance.path().join("tit.sqlite3"))
        .expect("open the push audit database");
    let successful: i64 = database
        .query_row(
            "SELECT count(*) FROM audit_event
             WHERE action = 'ref.update' AND actor = 'writer' AND outcome = 'success'",
            [],
            |row| row.get(0),
        )
        .expect("count successful push audit events");
    let failed: i64 = database
        .query_row(
            "SELECT count(*) FROM audit_event
             WHERE action = 'ref.update' AND actor = 'writer' AND outcome = 'failure'",
            [],
            |row| row.get(0),
        )
        .expect("count failed push audit events");
    assert_eq!(successful, 3);
    assert!(failed >= 2);
}

fn spawn_server(config: &Path) -> ChildGuard {
    let child = Command::new(tit_binary())
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
        tit_binary()
    } else {
        "git".into()
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

fn tit_binary() -> std::path::PathBuf {
    env::var_os("TIT_RELEASE_BINARY")
        .map(Into::into)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_tit").into())
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
    http_get_with_headers(address, path, &[])
}

fn http_get_with_headers(address: SocketAddr, path: &str, headers: &[(&str, &str)]) -> String {
    let mut stream = TcpStream::connect(address).expect("connect to the HTTP server");
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("write an HTTP request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read an HTTP response");
    response
}

fn http_form(address: SocketAddr, path: &str, fields: &[(&str, &str)]) -> String {
    http_form_with_headers(address, path, fields, &[])
}

fn http_form_with_headers(
    address: SocketAddr,
    path: &str,
    fields: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> String {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish();
    let mut stream = TcpStream::connect(address).expect("connect to the HTTP server");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body);
    stream
        .write_all(request.as_bytes())
        .expect("write an HTTP form");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read an HTTP response");
    response
}

fn response_cookies(response: &str) -> String {
    response
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| {
            value
                .trim()
                .split_once(';')
                .map_or(value.trim(), |(cookie, _)| cookie)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn response_header<'a>(response: &'a str, name: &str) -> &'a str {
    response
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .expect("read a response header")
}

fn http_multipart(
    address: SocketAddr,
    path: &str,
    fields: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> String {
    let boundary = "tit-test-boundary";
    let mut body = String::new();
    for (name, value) in fields {
        if *name == "signature-file" {
            body.push_str(&format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"signature.sig\"\r\nContent-Type: application/octet-stream\r\n\r\n{value}\r\n"
            ));
        } else {
            body.push_str(&format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            ));
        }
    }
    body.push_str(&format!("--{boundary}--\r\n"));
    let mut stream = TcpStream::connect(address).expect("connect to the HTTP server");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body);
    stream
        .write_all(request.as_bytes())
        .expect("write a multipart HTTP form");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read an HTTP response");
    response
}

fn http_body(
    address: SocketAddr,
    path: &str,
    content_type: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> String {
    let mut stream = TcpStream::connect(address).expect("connect to the HTTP server");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream
        .write_all(request.as_bytes())
        .expect("write an HTTP request body");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read an HTTP response");
    response
}

fn cookie_value<'a>(cookies: &'a str, name: &str) -> &'a str {
    cookies
        .split("; ")
        .find_map(|cookie| cookie.strip_prefix(&format!("{name}=")))
        .expect("find the cookie")
}

fn sign_challenge(directory: &Path, private_key: &Path, challenge: &str) -> String {
    let nonce = challenge
        .lines()
        .find_map(|line| line.strip_prefix("nonce="))
        .expect("find the Web login nonce");
    let path = directory.join(format!("web-login-{nonce}.challenge"));
    fs::write(&path, challenge).expect("write the Web login challenge");
    let output = Command::new("ssh-keygen")
        .args(["-q", "-Y", "sign", "-f"])
        .arg(private_key)
        .args(["-n", "tit-auth"])
        .arg(&path)
        .output()
        .expect("sign the Web login challenge");
    assert!(
        output.status.success(),
        "cannot sign the Web login challenge: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::read_to_string(path.with_extension("challenge.sig")).expect("read the Web login signature")
}

fn between<'a>(value: &'a str, start: &str, end: &str) -> &'a str {
    value
        .split_once(start)
        .and_then(|(_, tail)| tail.split_once(end))
        .map(|(value, _)| value)
        .expect("find the response value")
}

fn ssh_clone_succeeds(address: SocketAddr, private_key: &Path, target: &Path) -> bool {
    ssh_clone_repository_succeeds(address, private_key, "alice", "example", target)
}

fn ssh_clone_repository_succeeds(
    address: SocketAddr,
    private_key: &Path,
    owner: &str,
    repository: &str,
    target: &Path,
) -> bool {
    let ssh_command = format!(
        "ssh -F /dev/null -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        private_key.display()
    );
    Command::new("git")
        .args([
            "clone",
            "-q",
            &format!(
                "ssh://ignored@127.0.0.1:{}/{owner}/{repository}.git",
                address.port(),
            ),
        ])
        .arg(target)
        .env("GIT_SSH_COMMAND", ssh_command)
        .output()
        .expect("clone through the tit SSH server")
        .status
        .success()
}

fn ssh_exec(address: SocketAddr, private_key: &Path, command: &[&str]) -> Output {
    Command::new("ssh")
        .args([
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
            "-i",
        ])
        .arg(private_key)
        .args(["-p", &address.port().to_string()])
        .arg(format!("ignored@{}", address.ip()))
        .args(command)
        .output()
        .expect("run an SSH repository command")
}

fn ssh_exec_with_input(
    address: SocketAddr,
    private_key: &Path,
    command: &[&str],
    input: &[u8],
) -> Output {
    let mut child = Command::new("ssh")
        .args([
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
            "-i",
        ])
        .arg(private_key)
        .args(["-p", &address.port().to_string()])
        .arg(format!("ignored@{}", address.ip()))
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start an SSH issue command");
    child
        .stdin
        .take()
        .expect("open SSH issue input")
        .write_all(input)
        .expect("write SSH issue input");
    child
        .wait_with_output()
        .expect("finish an SSH issue command")
}

fn provision_account(
    instance: &Path,
    username: &str,
    state: &str,
    revoked: bool,
) -> std::path::PathBuf {
    let private_key = instance.join(username);
    create_ssh_key_fixture(&private_key);
    let public_key =
        fs::read_to_string(private_key.with_extension("pub")).expect("read an account public key");
    let mut fields = public_key.split_whitespace();
    let canonical = format!(
        "{} {}",
        fields.next().expect("read the key algorithm"),
        fields.next().expect("read the key data")
    );
    let fingerprint_output = Command::new("ssh-keygen")
        .args(["-E", "sha256", "-lf"])
        .arg(private_key.with_extension("pub"))
        .output()
        .expect("read an SSH key fingerprint");
    assert!(fingerprint_output.status.success());
    let fingerprint_text =
        String::from_utf8(fingerprint_output.stdout).expect("read a UTF-8 SSH key fingerprint");
    let fingerprint = fingerprint_text
        .split_whitespace()
        .nth(1)
        .expect("read the SSH key fingerprint");
    let database = rusqlite::Connection::open(instance.join("tit.sqlite3"))
        .expect("open the repository database");
    database
        .execute(
            "INSERT INTO account (username, is_administrator, state, created_at)
             VALUES (?1, 0, ?2, 1)",
            rusqlite::params![username, state],
        )
        .expect("create an account fixture");
    let account_id = database.last_insert_rowid();
    database
        .execute(
            "INSERT INTO ssh_public_key
             (account_id, canonical_key, fingerprint, created_at, label, revoked_at)
             VALUES (?1, ?2, ?3, 1, 'initial', ?4)",
            rusqlite::params![account_id, canonical, fingerprint, revoked.then_some(2)],
        )
        .expect("create an SSH key fixture");
    private_key
}

fn git_commit(worktree: &Path, message: &str) {
    command(worktree, ["add", "."]);
    let output = Command::new("git")
        .args(["commit", "-q", "-m", message])
        .env("GIT_AUTHOR_NAME", "Tit Test")
        .env("GIT_AUTHOR_EMAIL", "tit@example.test")
        .env("GIT_COMMITTER_NAME", "Tit Test")
        .env("GIT_COMMITTER_EMAIL", "tit@example.test")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "commit.gpgsign")
        .env("GIT_CONFIG_VALUE_0", "false")
        .current_dir(worktree)
        .output()
        .expect("commit a Git change");
    assert!(
        output.status.success(),
        "Git commit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_push(private_key: &Path, worktree: &Path, refspecs: &[&str]) -> ExitStatus {
    git_push_output(private_key, worktree, refspecs).status
}

fn git_push_output(private_key: &Path, worktree: &Path, refspecs: &[&str]) -> Output {
    let ssh_command = format!(
        "ssh -F /dev/null -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        private_key.display()
    );
    Command::new("git")
        .arg("push")
        .arg("origin")
        .args(refspecs)
        .env("GIT_SSH_COMMAND", ssh_command)
        .current_dir(worktree)
        .output()
        .expect("push through the tit SSH server")
}

fn git_fetch_ref(private_key: &Path, worktree: &Path, refspec: &str) -> ExitStatus {
    let ssh_command = format!(
        "ssh -F /dev/null -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        private_key.display()
    );
    Command::new("git")
        .args(["fetch", "origin", refspec])
        .env("GIT_SSH_COMMAND", ssh_command)
        .current_dir(worktree)
        .status()
        .expect("fetch through the tit SSH server")
}

fn git_revision(worktree: &Path, revision: &str) -> String {
    let output = Command::new("git")
        .args(["rev-parse", revision])
        .current_dir(worktree)
        .output()
        .expect("resolve a Git revision");
    assert!(
        output.status.success(),
        "cannot resolve Git revision: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("read a Git revision")
        .trim()
        .to_owned()
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn terminate_capture(&mut self) -> Vec<u8> {
        let child = self.0.take().expect("the server process is active");
        let signal = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .output()
            .expect("send SIGTERM to the tit server");
        assert!(signal.status.success(), "cannot send SIGTERM");
        let output = child
            .wait_with_output()
            .expect("wait for the tit server and read its output");
        assert!(
            output.status.success(),
            "tit serve did not stop cleanly: {}",
            output.status
        );
        output.stderr
    }

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
