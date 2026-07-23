#[allow(
    dead_code,
    reason = "the public-route test uses only username validation"
)]
#[path = "../src/auth.rs"]
mod auth;
#[path = "../src/domain/mod.rs"]
mod domain;
#[allow(
    dead_code,
    reason = "the public-route test does not use each shared Git API"
)]
#[path = "../src/git/mod.rs"]
mod git;
#[allow(
    dead_code,
    reason = "the public-route test uses the public Web server only"
)]
#[path = "../src/http/mod.rs"]
mod http;
#[allow(
    dead_code,
    reason = "the public-route test creates instance files directly"
)]
#[path = "../src/instance.rs"]
mod instance;
#[allow(
    dead_code,
    reason = "the public-route test does not use each store API"
)]
#[path = "../src/store/mod.rs"]
mod store;

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;

use http::{PublicWebConfig, RunningWebServer};
use store::{InitialAdministrator, NewRepository, Store};
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browses_and_clones_public_repositories_for_both_hash_formats() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new(format);
        let server = RunningWebServer::start_public(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            PublicWebConfig {
                instance_dir: fixture.instance.path().to_owned(),
                http_clone_base: "https://tit.example".to_owned(),
                ssh_clone_base: "ssh://tit.example:2222".to_owned(),
            },
        )
        .await
        .expect("start the public Web server");

        let summary = request(server.address(), "GET", "/alice/example", &[], &[]);
        assert_eq!(summary.status, 200);
        assert_html_policy(&summary);
        let summary_text = summary.text();
        assert!(summary_text.contains("<h1><a href=\"/alice/example\">alice/example</a></h1>"));
        assert!(summary_text.contains("https://tit.example/alice/example"));
        assert!(summary_text.contains("ssh://tit.example:2222/alice/example"));
        assert!(summary_text.contains(&fixture.head));
        assert!(summary_text.contains("README.md"));
        assert!(summary_text.contains("tit fixture &#60;safe&#62;"));
        assert!(!summary_text.contains("<script"));

        let empty = request(server.address(), "GET", "/alice/empty", &[], &[]);
        assert_eq!(empty.status, 200);
        assert!(empty.text().contains("This repository has no commits."));

        let alias = request(server.address(), "GET", "/alice/example.git", &[], &[]);
        assert_eq!(alias.status, 308);
        assert_eq!(alias.header("location"), "/alice/example");

        let routes = [
            "/alice/example/refs".to_owned(),
            format!("/alice/example/commit/{}", fixture.head),
            format!("/alice/example/tree/{}", fixture.head),
            format!("/alice/example/tree/{}/nested", fixture.head),
            format!("/alice/example/blob/{}/nested/file.txt", fixture.head),
            format!("/alice/example/diff/{}/{}", fixture.parent, fixture.head),
            format!("/alice/example/blame/{}/nested/file.txt", fixture.head),
        ];
        for route in &routes {
            let response = request(server.address(), "GET", route, &[], &[]);
            assert_eq!(response.status, 200, "route failed: {route}");
            assert_html_policy(&response);
            assert!(!response.text().to_ascii_lowercase().contains("<script"));

            let head = request(server.address(), "HEAD", route, &[], &[]);
            assert_eq!(head.status, 200, "HEAD failed: {route}");
            assert!(head.body.is_empty());
            assert_eq!(
                head.header("content-length"),
                response.body.len().to_string()
            );
        }

        let tree = request(
            server.address(),
            "GET",
            &format!("/alice/example/tree/{}", fixture.head),
            &[],
            &[],
        );
        let tree_text = tree.text();
        assert!(tree_text.contains("README.md"));
        assert!(tree_text.contains("binary.dat"));
        assert!(tree_text.contains("non-å.txt"));
        assert!(tree_text.contains("non-%C3%A5.txt"));

        let blob = request(
            server.address(),
            "GET",
            &format!("/alice/example/blob/{}/nested/file.txt", fixture.head),
            &[],
            &[],
        );
        assert!(blob.text().contains("second line"));
        assert!(blob.text().contains(&format!(
            "/alice/example/raw/{}/nested/file.txt",
            fixture.head
        )));

        let binary = request(
            server.address(),
            "GET",
            &format!("/alice/example/blob/{}/binary.dat", fixture.head),
            &[],
            &[],
        );
        assert_eq!(binary.status, 200);
        assert!(binary.text().contains("Binary content cannot be shown."));

        let raw = request(
            server.address(),
            "GET",
            &format!("/alice/example/raw/{}/nested/file.txt", fixture.head),
            &[],
            &[],
        );
        assert_eq!(raw.status, 200);
        assert_eq!(raw.header("content-type"), "application/octet-stream");
        assert_eq!(raw.body, b"first line\nsecond line\n");
        assert_eq!(
            raw.header("cache-control"),
            "public, max-age=31536000, immutable"
        );
        let raw_head = request(
            server.address(),
            "HEAD",
            &format!("/alice/example/raw/{}/nested/file.txt", fixture.head),
            &[],
            &[],
        );
        assert_eq!(raw_head.status, 200);
        assert!(raw_head.body.is_empty());
        assert_eq!(
            raw_head.header("content-length"),
            raw.body.len().to_string()
        );

        let non_utf8 = request(
            server.address(),
            "GET",
            &format!("/alice/example/raw/{}/non-%C3%A5.txt", fixture.head),
            &[],
            &[],
        );
        assert_eq!(non_utf8.status, 200);
        assert_eq!(non_utf8.body, b"non-UTF-8 path\n");
        let missing_non_utf8 = request(
            server.address(),
            "GET",
            &format!("/alice/example/raw/{}/missing-%FF.txt", fixture.head),
            &[],
            &[],
        );
        assert_eq!(missing_non_utf8.status, 404);
        assert_html_policy(&missing_non_utf8);

        let archive = request(
            server.address(),
            "GET",
            &format!("/alice/example/archive/{}.tar", fixture.head),
            &[],
            &[],
        );
        assert_eq!(archive.status, 200);
        assert_eq!(archive.header("content-type"), "application/x-tar");
        assert!(archive.body.ends_with(&[0_u8; 1024]));
        let archive_head = request(
            server.address(),
            "HEAD",
            &format!("/alice/example/archive/{}.tar", fixture.head),
            &[],
            &[],
        );
        assert_eq!(archive_head.status, 200);
        assert!(archive_head.body.is_empty());
        let archive_path = fixture.instance.path().join(format!("{format}.tar"));
        fs::write(&archive_path, &archive.body).expect("write the public archive");
        let listed = Command::new("tar")
            .arg("-tf")
            .arg(&archive_path)
            .output()
            .expect("run the system tar reader");
        assert!(listed.status.success());
        let names = String::from_utf8_lossy(&listed.stdout);
        assert!(names.contains("README.md"));
        assert!(names.contains("nested/file.txt"));

        let discovery = request(
            server.address(),
            "GET",
            "/alice/example.git/info/refs?service=git-upload-pack",
            &[("Git-Protocol", "version=2")],
            &[],
        );
        assert_eq!(discovery.status, 200);
        assert_eq!(
            discovery.header("content-type"),
            "application/x-git-upload-pack-advertisement"
        );
        assert!(
            discovery
                .body
                .windows(b"version 2".len())
                .any(|window| window == b"version 2")
        );
        assert_eq!(
            request(
                server.address(),
                "GET",
                "/alice/example/info/refs?service=git-receive-pack",
                &[],
                &[],
            )
            .status,
            400
        );
        assert_eq!(
            request(
                server.address(),
                "GET",
                "/alice/example/info/refs?service=git-upload-pack",
                &[("Git-Protocol", "version=3")],
                &[],
            )
            .status,
            400
        );
        assert_eq!(
            request(
                server.address(),
                "POST",
                "/alice/example/git-upload-pack",
                &[("Content-Type", "text/plain")],
                b"0000",
            )
            .status,
            415
        );
        assert_eq!(
            request(
                server.address(),
                "POST",
                "/alice/example/git-upload-pack",
                &[
                    ("Content-Type", "application/x-git-upload-pack-request"),
                    ("Git-Protocol", "version=2"),
                ],
                b"zzzz",
            )
            .status,
            400
        );
        assert_eq!(
            request(
                server.address(),
                "POST",
                "/alice/example/git-upload-pack",
                &[("Content-Type", "application/x-git-upload-pack-request")],
                &vec![b'0'; git::packetline::MAX_REQUEST_BYTES + 1],
            )
            .status,
            413
        );

        let clone = fixture.instance.path().join(format!("clone-{format}"));
        run(Command::new("git")
            .args(["-c", "protocol.version=2", "clone", "-q"])
            .arg(format!("http://{}/alice/example.git", server.address()))
            .arg(&clone));
        assert_eq!(rev_parse(&clone, "HEAD"), fixture.head);
        assert_eq!(
            fs::read(clone.join("nested/file.txt")).expect("read the cloned file"),
            b"first line\nsecond line\n"
        );

        for route in [
            "/alice/missing",
            "/Alice/example",
            "/alice/example/commit/not-an-object",
            "/alice/example/tree/0000000000000000000000000000000000000000",
            "/alice/example/raw/0000000000000000000000000000000000000000/file",
        ] {
            let response = request(server.address(), "GET", route, &[], &[]);
            assert_eq!(response.status, 404, "route leaked or accepted: {route}");
            assert_html_policy(&response);
        }

        let database = fixture.instance.path().join(store::DATABASE_FILE);
        let hidden = Store::open(&database).expect("open the repository database");
        hidden
            .connection()
            .execute(
                "UPDATE repository SET visibility = 'private' WHERE slug = 'example'",
                [],
            )
            .expect("make the repository private");
        drop(hidden);
        assert_hidden(server.address(), &fixture.head);

        let archived = Store::open(&database).expect("reopen the repository database");
        archived
            .connection()
            .execute(
                "UPDATE repository
                 SET visibility = 'public', state = 'archived', archived_at = 3
                 WHERE slug = 'example'",
                [],
            )
            .expect("archive the repository");
        drop(archived);
        assert_hidden(server.address(), &fixture.head);

        server.shutdown().await.expect("stop the public Web server");
    }
}

fn assert_hidden(address: SocketAddr, head: &str) {
    for route in [
        "/alice/example".to_owned(),
        format!("/alice/example/raw/{head}/README.md"),
        "/alice/example/info/refs?service=git-upload-pack".to_owned(),
    ] {
        let response = request(address, "GET", &route, &[], &[]);
        assert_eq!(response.status, 404, "repository was visible at {route}");
    }
}

struct Fixture {
    instance: TempDir,
    head: String,
    parent: String,
}

impl Fixture {
    fn new(format: &str) -> Self {
        let instance = TempDir::new().expect("create an instance directory");
        let repositories = instance.path().join("repositories");
        fs::create_dir(&repositories).expect("create the repository directory");
        let id = if format == "sha1" {
            "11111111111111111111111111111111"
        } else {
            "22222222222222222222222222222222"
        };
        let bare = repositories.join(format!("{id}.git"));
        let empty_bare = repositories.join("33333333333333333333333333333333.git");
        let worktree = instance.path().join("worktree");

        run(Command::new("git")
            .args(["init", "-q", "-b", "main", "--object-format", format])
            .arg(&worktree));
        fs::write(worktree.join("README.md"), b"# tit fixture <safe>\n").expect("write the README");
        fs::create_dir(worktree.join("nested")).expect("create a nested directory");
        fs::write(worktree.join("nested/file.txt"), b"first line\n").expect("write the text file");
        fs::write(worktree.join("binary.dat"), b"binary\0content").expect("write the binary file");
        fs::write(worktree.join("non-å.txt"), b"non-UTF-8 path\n")
            .expect("write the percent-encoded path");
        commit_all(&worktree, "first commit");
        let parent = rev_parse(&worktree, "HEAD");
        fs::write(
            worktree.join("nested/file.txt"),
            b"first line\nsecond line\n",
        )
        .expect("update the text file");
        commit_all(&worktree, "second commit");
        let head = rev_parse(&worktree, "HEAD");

        run(Command::new("git")
            .args(["init", "-q", "--bare", "--object-format", format])
            .arg(&bare));
        run(Command::new("git")
            .args(["init", "-q", "--bare", "--object-format", format])
            .arg(&empty_bare));
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
            .create_repository(&NewRepository {
                id,
                owner: "alice",
                slug: "example",
                object_format: format,
                created_at: 2,
            })
            .expect("create the repository record");
        store
            .create_repository(&NewRepository {
                id: "33333333333333333333333333333333",
                owner: "alice",
                slug: "empty",
                object_format: format,
                created_at: 2,
            })
            .expect("create the empty repository record");
        drop(store);

        Self {
            instance,
            head,
            parent,
        }
    }
}

fn commit_all(worktree: &Path, message: &str) {
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["add", "-A"]));
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["commit", "-q", "-m", message])
        .env("GIT_AUTHOR_NAME", "Fixture Author")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.test")
        .env("GIT_COMMITTER_NAME", "Fixture Author")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.test"));
}

fn rev_parse(repository: &Path, revision: &str) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", revision])
        .output()
        .expect("read a Git object ID");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("a hexadecimal object ID")
        .trim()
        .to_owned()
}

fn run(command: &mut Command) {
    let output = command.output().expect("run a fixture command");
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let mut stream = TcpStream::connect(address).expect("connect to the public Web server");
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
        .and_then(|()| stream.write_all(body))
        .expect("write an HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read an HTTP response");
    HttpResponse::parse(&response)
}

fn assert_html_policy(response: &HttpResponse) {
    assert_eq!(response.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(response.header("x-content-type-options"), "nosniff");
    assert_eq!(response.header("x-frame-options"), "DENY");
    assert_eq!(response.header("referrer-policy"), "no-referrer");
    assert_eq!(response.header("cache-control"), "no-store");
    assert_eq!(response.header("x-request-id").len(), 32);
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
