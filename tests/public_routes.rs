use crate::{http, store};

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{PublicWebConfig, RunningWebServer};
use sha2::{Digest, Sha256};
use store::{InitialAdministrator, NewRepository, RepositoryOrigin, Store};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renders_and_mutates_a_public_issue_without_javascript() {
    let fixture = Fixture::new();
    let database = fixture.instance.path().join(store::DATABASE_FILE);
    let server = RunningWebServer::start_public(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        PublicWebConfig {
            instance_dir: fixture.instance.path().to_owned(),
            http_clone_base: "https://tit.example".to_owned(),
            ssh_clone_base: "ssh://tit.example:2222".to_owned(),
            trusted_proxy: None,
            max_request_bytes: 1024 * 1024,
            max_connections: 32,
        },
    )
    .await
    .expect("start the public Web server");

    let summary = request(server.address(), "GET", "/alice/example", &[], &[]).await;
    assert_eq!(summary.status, 200);
    assert_html_policy(&summary);
    assert!(
        summary
            .text()
            .contains("alice</a>/<a href=\"/alice/example\"")
    );
    assert!(summary.text().contains("<h1>tit fixture</h1>"));
    assert!(!summary.text().to_ascii_lowercase().contains("<script"));
    assert!(summary.text().contains("/alice/example/issues"));

    let anonymous_issues =
        request(server.address(), "GET", "/alice/example/issues", &[], &[]).await;
    assert_eq!(anonymous_issues.status, 200);
    assert!(
        anonymous_issues
            .text()
            .contains("This repository has no issues.")
    );
    assert!(!anonymous_issues.text().contains("Create an issue</h2>"));
    assert!(
        anonymous_issues
            .text()
            .contains("href=\"/alice/example/issues/rss.xml\"")
    );
    let issue_feed = request(
        server.address(),
        "GET",
        "/alice/example/issues/rss.xml",
        &[],
        &[],
    )
    .await;
    assert_eq!(issue_feed.status, 200);
    assert_eq!(
        issue_feed.header("content-type"),
        "application/rss+xml; charset=utf-8"
    );
    assert!(
        issue_feed
            .text()
            .contains("<title>alice/example issues</title>")
    );
    assert!(issue_feed.text().contains(
        "<atom:link rel=\"self\" href=\"https://tit.example/alice/example/issues/rss.xml\" />"
    ));

    let pull_requests = request(server.address(), "GET", "/alice/example/pulls", &[], &[]).await;
    assert_eq!(pull_requests.status, 200);
    assert!(
        pull_requests
            .text()
            .contains("href=\"/alice/example/pulls/rss.xml\"")
    );
    let pull_request_feed = request(
        server.address(),
        "GET",
        "/alice/example/pulls/rss.xml",
        &[],
        &[],
    )
    .await;
    assert_eq!(pull_request_feed.status, 200);
    assert_eq!(
        pull_request_feed.header("content-type"),
        "application/rss+xml; charset=utf-8"
    );
    assert!(
        pull_request_feed
            .text()
            .contains("<title>alice/example pull requests</title>")
    );
    assert!(pull_request_feed.text().contains(
        "<atom:link rel=\"self\" href=\"https://tit.example/alice/example/pulls/rss.xml\" />"
    ));
    assert!(!pull_request_feed.text().contains("Repository imported"));

    let token = "11".repeat(32);
    let csrf = "22".repeat(32);
    create_session(&database, &token, &csrf);
    let cookie = format!("tit-session={token}; tit-csrf={csrf}");
    let headers = [
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Cookie", cookie.as_str()),
    ];
    let organization_profile = request(server.address(), "GET", "/acme", &[], &[]).await;
    assert_eq!(organization_profile.status, 200);
    assert!(
        organization_profile
            .text()
            .contains("<h1 id=\"profile-heading\">Acme Organization</h1>")
    );
    assert!(organization_profile.text().contains("alice</a> · owner"));
    assert!(!organization_profile.text().contains("Edit organization"));
    assert!(!organization_profile.text().contains("Add or update member"));
    let account_profile = request(server.address(), "GET", "/alice", &[], &[]).await;
    assert_eq!(account_profile.status, 200);
    assert!(
        account_profile
            .text()
            .contains("<a href=\"/acme\">Acme Organization</a> · owner")
    );
    assert!(
        account_profile
            .text()
            .contains("<h2 id=\"activity-heading\">Activity</h2>")
    );
    assert!(
        account_profile
            .text()
            .contains("0 active days in the past year")
    );
    let account = request(
        server.address(),
        "GET",
        "/account",
        &[("Cookie", cookie.as_str())],
        &[],
    )
    .await;
    assert_eq!(account.status, 200);
    assert!(!account.text().contains("<h2>Create repository</h2>"));
    assert!(account.text().contains("<strong>Feeds</strong>"));
    assert!(account.text().contains("<strong>Sessions</strong>"));
    assert!(
        account
            .text()
            .contains("href=\"/new\" aria-label=\"Create\"")
    );
    let create_page = request(
        server.address(),
        "GET",
        "/new",
        &[("Cookie", cookie.as_str())],
        &[],
    )
    .await;
    assert_eq!(create_page.status, 200);
    assert!(create_page.text().contains("href=\"/new/repository\""));
    assert!(create_page.text().contains("href=\"/new/organization\""));
    let repository_page = request(
        server.address(),
        "GET",
        "/new/repository",
        &[("Cookie", cookie.as_str())],
        &[],
    )
    .await;
    assert_eq!(repository_page.status, 200);
    assert!(
        repository_page
            .text()
            .contains("<option value=\"acme\">acme</option>")
    );
    assert!(
        repository_page
            .text()
            .contains("<h1>Create repository</h1>")
    );
    let organization_page = request(
        server.address(),
        "GET",
        "/new/organization",
        &[("Cookie", cookie.as_str())],
        &[],
    )
    .await;
    assert_eq!(organization_page.status, 200);
    assert!(
        organization_page
            .text()
            .contains("<h1>Create organization</h1>")
    );
    let organization = form(&[
        ("csrf", &csrf),
        ("name", "tools"),
        ("display-name", "Tools"),
        ("description", "Shared tools."),
    ]);
    let created_organization = request(
        server.address(),
        "POST",
        "/organizations",
        &headers,
        organization.as_bytes(),
    )
    .await;
    assert_eq!(created_organization.status, 303);
    assert_eq!(created_organization.header("location"), "/tools");
    let managed_organization = request(
        server.address(),
        "GET",
        "/acme",
        &[("Cookie", cookie.as_str())],
        &[],
    )
    .await;
    assert_eq!(managed_organization.status, 200);
    assert!(
        managed_organization
            .text()
            .contains("<h2>Edit organization</h2>")
    );
    assert!(managed_organization.text().contains("Add or update member"));
    let member = form(&[("csrf", &csrf), ("username", "bob"), ("role", "writer")]);
    let member_set = request(
        server.address(),
        "POST",
        "/organizations/acme/members",
        &headers,
        member.as_bytes(),
    )
    .await;
    assert_eq!(member_set.status, 303);
    let bob_profile = request(server.address(), "GET", "/bob", &[], &[]).await;
    assert!(
        bob_profile
            .text()
            .contains("<a href=\"/acme\">Acme Organization</a> · writer")
    );
    let profile_update = form(&[
        ("csrf", &csrf),
        ("display-name", "Acme Cooperative"),
        ("description", "A changed organization profile."),
    ]);
    let updated_organization = request(
        server.address(),
        "POST",
        "/organizations/acme/profile",
        &headers,
        profile_update.as_bytes(),
    )
    .await;
    assert_eq!(updated_organization.status, 303);
    assert_eq!(updated_organization.header("location"), "/acme");
    let organization_profile = request(server.address(), "GET", "/acme", &[], &[]).await;
    assert!(organization_profile.text().contains("Acme Cooperative"));
    assert!(
        organization_profile
            .text()
            .contains("A changed organization profile.")
    );
    let organization_repository = form(&[
        ("csrf", &csrf),
        ("owner", "acme"),
        ("name", "organization-project"),
    ]);
    let created_repository = request(
        server.address(),
        "POST",
        "/account/repositories",
        &headers,
        organization_repository.as_bytes(),
    )
    .await;
    assert_eq!(created_repository.status, 303);
    assert_eq!(
        created_repository.header("location"),
        "/acme/organization-project"
    );
    assert_eq!(
        request(
            server.address(),
            "GET",
            "/acme/organization-project",
            &[],
            &[],
        )
        .await
        .status,
        200
    );

    let rejected = form(&[
        ("csrf", &"33".repeat(32)),
        ("title", "Rejected issue"),
        ("body", "This must not be stored."),
    ]);
    assert_eq!(
        request(
            server.address(),
            "POST",
            "/alice/example/issues",
            &headers,
            rejected.as_bytes(),
        )
        .await
        .status,
        403
    );

    let issue = form(&[
        ("csrf", &csrf),
        ("title", "No JavaScript workflow"),
        ("body", "**safe**\n\n<script>alert(1)</script>"),
    ]);
    let created = request(
        server.address(),
        "POST",
        "/alice/example/issues",
        &headers,
        issue.as_bytes(),
    )
    .await;
    assert_eq!(created.status, 303);
    assert_eq!(created.header("location"), "/alice/example/issues/1");

    let detail = request(
        server.address(),
        "GET",
        "/alice/example/issues/1",
        &[("Cookie", cookie.as_str())],
        &[],
    )
    .await;
    assert_eq!(detail.status, 200);
    assert!(detail.text().contains("#1 No JavaScript workflow"));
    assert!(detail.text().contains("<strong>safe</strong>"));
    assert!(!detail.text().to_ascii_lowercase().contains("<script"));
    let active_profile = request(server.address(), "GET", "/alice", &[], &[]).await;
    assert!(
        active_profile
            .text()
            .contains("1 active day in the past year")
    );
    assert!(active_profile.text().contains("activity-level-2"));

    Store::open(&database)
        .expect("open the repository database")
        .connection()
        .execute(
            "UPDATE repository SET visibility = 'private' WHERE slug = 'example'",
            [],
        )
        .expect("make the repository private");
    assert_eq!(
        request(server.address(), "GET", "/alice/example", &[], &[])
            .await
            .status,
        404
    );
    assert_eq!(
        request(
            server.address(),
            "GET",
            "/alice/example",
            &[("Cookie", cookie.as_str())],
            &[],
        )
        .await
        .status,
        200
    );
    let private_profile = request(server.address(), "GET", "/alice", &[], &[]).await;
    assert!(
        private_profile
            .text()
            .contains("1 active day in the past year")
    );

    server.shutdown().await.expect("stop the public Web server");
}

fn create_session(database: &Path, token: &str, csrf: &str) {
    let session_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let csrf_hash: [u8; 32] = Sha256::digest(csrf.as_bytes()).into();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("read the current time")
        .as_secs() as i64;
    Store::open(database)
        .expect("open the session database")
        .connection()
        .execute(
            "INSERT INTO web_session
             (session_hash, csrf_hash, account_id, created_at, expires_at)
             SELECT ?1, ?2, id, ?3, ?4 FROM account WHERE username = 'alice'",
            rusqlite::params![session_hash, csrf_hash, now, now + 3_600],
        )
        .expect("create a Web session");
}

fn form(fields: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(fields.iter().copied());
    serializer.finish()
}

struct Fixture {
    instance: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let instance = TempDir::new().expect("create an instance directory");
        let repositories = instance.path().join("repositories");
        fs::create_dir(&repositories).expect("create the repository directory");
        let worktree = instance.path().join("worktree");
        let repository_id = "11111111111111111111111111111111";
        let bare = repositories.join(format!("{repository_id}.git"));

        run(Command::new("git")
            .args(["init", "-q", "-b", "main"])
            .arg(&worktree));
        run(Command::new("git").arg("-C").arg(&worktree).args([
            "config",
            "commit.gpgsign",
            "false",
        ]));
        fs::write(
            worktree.join("README.md"),
            "# tit fixture\n\n**safe**\n\n<script>alert(1)</script>\n",
        )
        .expect("write the README");
        run(Command::new("git")
            .arg("-C")
            .arg(&worktree)
            .args(["add", "README.md"]));
        run(Command::new("git")
            .arg("-C")
            .arg(&worktree)
            .args(["commit", "-q", "-m", "initial commit"])
            .env("GIT_AUTHOR_NAME", "Fixture Author")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.test")
            .env("GIT_COMMITTER_NAME", "Fixture Author")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.test"));
        run(Command::new("git")
            .args(["init", "-q", "--bare"])
            .arg(&bare));
        run(Command::new("git").arg("-C").arg(&bare).args([
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        ]));
        run(Command::new("git")
            .arg("-C")
            .arg(&worktree)
            .args(["push", "-q"])
            .arg(&bare)
            .arg("main"));

        let database = instance.path().join(store::DATABASE_FILE);
        let mut store = Store::open(&database).expect("open the fixture database");
        store
            .create_initial_administrator(&InitialAdministrator {
                username: "alice",
                canonical_key: "ssh-ed25519 AAAA",
                fingerprint: "SHA256:fixture",
                recovery_hash: &[7_u8; 32],
                created_at: 1,
            })
            .expect("create the repository owner");
        store
            .connection()
            .execute(
                "INSERT INTO account
                 (username, is_administrator, state, created_at)
                 VALUES ('bob', 0, 'active', 1)",
                [],
            )
            .expect("create an organization member");
        store
            .create_repository(&NewRepository {
                id: repository_id,
                owner: "alice",
                slug: "example",
                object_format: "sha1",
                default_branch: "refs/heads/main",
                created_at: 2,
                origin: RepositoryOrigin::Imported,
                initial_references: &[],
                actor: "admin-cli",
                correlation_id: "test-import",
            })
            .expect("create the repository record");
        store
            .create_organization(
                "acme",
                "Acme Organization",
                "A shared namespace.",
                "alice",
                3,
                "create-organization",
            )
            .expect("create the organization");

        Self { instance }
    }
}

fn run(command: &mut Command) {
    let output = command.output().expect("run a fixture command");
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let response = tokio::time::timeout(RESPONSE_TIMEOUT, async {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect to the public Web server");
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        stream
            .write_all(head.as_bytes())
            .await
            .expect("write HTTP request headers");
        stream
            .write_all(body)
            .await
            .expect("write the HTTP request");
        let mut response = Vec::new();
        if let Err(error) = stream.read_to_end(&mut response).await
            && error.kind() != std::io::ErrorKind::ConnectionReset
        {
            panic!("read an HTTP response: {error}");
        }
        response
    })
    .await
    .expect("receive an HTTP response before the deadline");
    HttpResponse::parse(&response)
}

fn assert_html_policy(response: &HttpResponse) {
    assert_eq!(response.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(response.header("x-content-type-options"), "nosniff");
    assert_eq!(response.header("x-frame-options"), "DENY");
    assert_eq!(response.header("referrer-policy"), "no-referrer");
    assert_eq!(response.header("cache-control"), "no-store");
}

struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn parse(bytes: &[u8]) -> Self {
        let split = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("an HTTP response header terminator");
        let head = std::str::from_utf8(&bytes[..split]).expect("UTF-8 HTTP response headers");
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .expect("an HTTP status line")
            .split_whitespace()
            .nth(1)
            .expect("an HTTP status code")
            .parse()
            .expect("a numeric HTTP status code");
        let headers = lines
            .map(|line| {
                let (name, value) = line.split_once(':').expect("a valid HTTP response header");
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect::<BTreeMap<_, _>>();
        let raw_body = &bytes[split + 4..];
        let body = if headers.get("transfer-encoding").map(String::as_str) == Some("chunked") {
            decode_chunked(raw_body)
        } else {
            raw_body.to_vec()
        };
        Self {
            status,
            headers,
            body,
        }
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("missing {name} response header"))
    }

    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).expect("a UTF-8 response body")
    }
}

fn decode_chunked(mut input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("a chunk-size terminator");
        let size_text = std::str::from_utf8(&input[..line_end]).expect("an ASCII chunk size");
        let size = usize::from_str_radix(size_text.split(';').next().expect("a chunk size"), 16)
            .expect("a hexadecimal chunk size");
        input = &input[line_end + 2..];
        if size == 0 {
            break;
        }
        assert!(input.len() >= size + 2, "a complete HTTP chunk");
        output.extend_from_slice(&input[..size]);
        assert_eq!(&input[size..size + 2], b"\r\n");
        input = &input[size + 2..];
    }
    output
}
