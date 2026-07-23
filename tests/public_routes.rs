#[allow(
    dead_code,
    reason = "the public-route test does not use account mutations"
)]
#[path = "../src/account.rs"]
mod account;
#[allow(
    dead_code,
    reason = "the public-route test uses only username validation"
)]
#[path = "../src/auth.rs"]
mod auth;
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "../src/feed.rs"]
mod feed;
#[path = "../src/feed_token.rs"]
mod feed_token;
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
#[allow(dead_code, reason = "the public-route test does not mutate issues")]
#[path = "../src/issue.rs"]
mod issue;
#[allow(dead_code, reason = "the public-route test does not run maintenance")]
#[path = "../src/maintenance.rs"]
mod maintenance;
#[path = "../src/markdown.rs"]
mod markdown;
#[allow(dead_code, reason = "the public-route test uses anonymous policy only")]
#[path = "../src/policy.rs"]
mod policy;
#[allow(
    dead_code,
    reason = "the public-route test does not mutate pull requests"
)]
#[path = "../src/pull_request.rs"]
mod pull_request;
#[path = "../src/rate_limit.rs"]
mod rate_limit;
#[allow(
    dead_code,
    reason = "the public route test does not create repositories through forms"
)]
#[path = "../src/repository.rs"]
mod repository;
#[path = "../src/search.rs"]
mod search;
#[allow(dead_code, reason = "the public-route test does not complete a login")]
#[path = "../src/session.rs"]
mod session;
#[allow(
    dead_code,
    reason = "the public-route test does not use each store API"
)]
#[path = "../src/store/mod.rs"]
mod store;
#[path = "../src/telemetry.rs"]
mod telemetry;
#[allow(dead_code, reason = "the public-route test does not change watches")]
#[path = "../src/watch.rs"]
mod watch;

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{PublicWebConfig, RunningWebServer};
use sha2::{Digest, Sha256};
use store::{InitialAdministrator, NewRepository, RepositoryOrigin, Store};
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
                max_request_bytes: 1024 * 1024,
                max_connections: 1024,
            },
        )
        .await
        .expect("start the public Web server");

        let summary = request(server.address(), "GET", "/alice/example", &[], &[]);
        assert_eq!(summary.status, 200);
        assert_html_policy(&summary);
        assert_repository_navigation(&summary, "alice", "example");
        let summary_text = summary.text();
        assert!(summary_text.contains("<h1><a href=\"/alice/example\">alice/example</a></h1>"));
        assert!(summary_text.contains("https://tit.example/alice/example"));
        assert!(summary_text.contains("ssh://tit.example:2222/alice/example"));
        assert!(summary_text.contains(&fixture.head));
        assert!(summary_text.contains("README.md"));
        assert!(summary_text.contains("<h1>tit fixture</h1>"));
        assert!(summary_text.contains("<strong>safe</strong>"));
        assert!(summary_text.contains("<code>&lt;safe&gt;</code>"));
        assert!(summary_text.contains("href=\"docs/guide.md\""));
        assert!(!summary_text.contains("<script"));
        assert!(!summary_text.contains("javascript:"));
        assert!(!summary_text.contains("<img"));
        assert!(!summary_text.contains("tracker.example"));
        assert!(summary_text.contains("&#60;script&#62;alert(3)&#60;/script&#62;"));
        assert!(summary_text.contains("/alice/example/atom.xml"));
        assert!(summary_text.contains("/alice/example/rss.xml"));
        assert!(summary_text.contains("/alice/example/search"));
        assert!(summary_text.contains("/alice/example/commits\">View all commits</a>"));
        assert_eq!(
            summary_text
                .matches("<li><a href=\"/alice/example/commit/")
                .count(),
            10
        );
        assert!(!summary_text.contains("Object format"));

        let commits = request(server.address(), "GET", "/alice/example/commits", &[], &[]);
        assert_eq!(commits.status, 200);
        assert_html_policy(&commits);
        assert_repository_navigation(&commits, "alice", "example");
        assert!(commits.text().contains("<h2>All commits</h2>"));
        assert_eq!(
            commits
                .text()
                .matches("<li><a href=\"/alice/example/commit/")
                .count(),
            12
        );
        let mut feed_entry_ids = Vec::new();
        for (path, content_type) in [
            (
                "/alice/example/atom.xml",
                "application/atom+xml; charset=utf-8",
            ),
            (
                "/alice/example/rss.xml",
                "application/rss+xml; charset=utf-8",
            ),
        ] {
            let feed = request(server.address(), "GET", path, &[], &[]);
            assert_eq!(feed.status, 200);
            assert_eq!(feed.header("content-type"), content_type);
            assert_eq!(feed.header("cache-control"), "public, max-age=60");
            assert!(!feed.header("etag").is_empty());
            assert!(!feed.header("last-modified").is_empty());
            let parsed = feed_rs::parser::parse(feed.body.as_slice()).expect("parse the feed");
            assert_eq!(parsed.entries.len(), 1);
            assert!(parsed.entries[0].id.starts_with("urn:tit:event:"));
            feed_entry_ids.push(parsed.entries[0].id.clone());
            assert!(feed.text().contains("Repository imported"));

            let etag = feed.header("etag");
            let conditional = request(
                server.address(),
                "GET",
                path,
                &[("If-None-Match", etag)],
                &[],
            );
            assert_eq!(conditional.status, 304);
            assert!(conditional.body.is_empty());

            let modified = request(
                server.address(),
                "GET",
                path,
                &[("If-Modified-Since", feed.header("last-modified"))],
                &[],
            );
            assert_eq!(modified.status, 304);
            assert!(modified.body.is_empty());

            let head = request(server.address(), "HEAD", path, &[], &[]);
            assert_eq!(head.status, 200);
            assert!(head.body.is_empty());
            assert_eq!(head.header("etag"), feed.header("etag"));
        }
        assert_eq!(feed_entry_ids[0], feed_entry_ids[1]);

        let invalid_page = request(
            server.address(),
            "GET",
            "/alice/example/atom.xml?before=0",
            &[],
            &[],
        );
        assert_eq!(invalid_page.status, 400);

        let database = fixture.instance.path().join("tit.sqlite3");
        let feed_store = Store::open(&database).expect("open the feed database");
        for timestamp in 10..35 {
            let actor = if timestamp == 34 {
                "x</title><script>alert(5)</script>"
            } else {
                "alice"
            };
            feed_store
                .connection()
                .execute(
                    "INSERT INTO repository_event
                     (event_id, repository_id, sequence, kind, actor, payload_version,
                      payload, created_at)
                     VALUES (
                         lower(hex(randomblob(16))),
                         ?1,
                         (SELECT COALESCE(MAX(sequence), 0) + 1
                          FROM repository_event WHERE repository_id = ?1),
                         'push', ?2, 1, '{\"version\":1}', ?3
                     )",
                    rusqlite::params![fixture.repository_id, actor, timestamp],
                )
                .expect("insert a page fixture event");
        }
        drop(feed_store);
        let first_page = request(server.address(), "GET", "/alice/example/atom.xml", &[], &[]);
        let first_feed =
            feed_rs::parser::parse(first_page.body.as_slice()).expect("parse the first page");
        assert_eq!(first_feed.entries.len(), 20);
        assert!(!first_page.text().contains("<script>"));
        assert!(first_page.text().contains("x&lt;/title&gt;&lt;script&gt;"));
        let next = first_page
            .text()
            .split("rel=\"next\" href=\"")
            .nth(1)
            .and_then(|value| value.split('\"').next())
            .expect("find the next-page URL")
            .replace("https://tit.example", "");
        let second_page = request(server.address(), "GET", &next, &[], &[]);
        let second_feed =
            feed_rs::parser::parse(second_page.body.as_slice()).expect("parse the second page");
        assert_eq!(second_feed.entries.len(), 6);
        assert!(!second_page.text().contains("rel=\"next\""));

        let empty = request(server.address(), "GET", "/alice/empty", &[], &[]);
        assert_eq!(empty.status, 200);
        assert!(empty.text().contains("This repository has no commits."));
        let empty_search = request(server.address(), "GET", "/alice/empty/search", &[], &[]);
        assert_eq!(empty_search.status, 200);
        assert!(
            empty_search
                .text()
                .contains("This repository has no commits to search.")
        );

        let alias = request(server.address(), "GET", "/alice/example.git", &[], &[]);
        assert_eq!(alias.status, 308);
        assert_eq!(alias.header("location"), "/alice/example");

        let routes = [
            "/alice/example/refs".to_owned(),
            "/alice/example/commits".to_owned(),
            "/alice/example/search".to_owned(),
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

        let search = request(
            server.address(),
            "GET",
            "/alice/example/search?q=second%20line&ref=HEAD",
            &[],
            &[],
        );
        assert_eq!(search.status, 200);
        assert_html_policy(&search);
        let search_text = search.text();
        assert!(search_text.contains("Found 1 matching lines."));
        assert!(search_text.contains("nested/file.txt:2"));
        assert!(search_text.contains(&format!(
            "/alice/example/blob/{}/nested/file.txt",
            fixture.head
        )));
        assert!(search_text.contains("<option value=\"HEAD\" selected>HEAD</option>"));

        let malformed = request(
            server.address(),
            "GET",
            "/alice/example/search?q=needle&ref=refs%2Fheads%2Fmain",
            &[],
            &[],
        );
        assert_eq!(malformed.status, 200);
        assert!(malformed.text().contains("malformed.txt:1"));
        assert!(malformed.text().contains("start � needle"));

        let escaped = request(
            server.address(),
            "GET",
            "/alice/example/search?q=%3Cscript%3E&ref=HEAD",
            &[],
            &[],
        );
        assert_eq!(escaped.status, 200);
        assert!(!escaped.text().contains("value=\"<script>\""));
        assert!(escaped.text().contains("value=\"&#60;script&#62;\""));
        assert_eq!(
            request(
                server.address(),
                "GET",
                "/alice/example/search?q=&ref=HEAD",
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
                "/alice/example/search?q=text&ref=refs%2Fheads%2Fmissing",
                &[],
                &[],
            )
            .status,
            404
        );

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
        assert!(tree_text.contains("&#60;img src=x onerror=alert(4)&#62;.txt"));
        assert!(!tree_text.contains("<img"));

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

        let large = request(
            server.address(),
            "GET",
            &format!("/alice/example/blob/{}/large.txt", fixture.head),
            &[],
            &[],
        );
        assert_eq!(large.status, 200);
        assert!(large.body.len() > 2 * 1024 * 1024);
        assert!(large.text().contains("large content starts"));
        assert!(large.text().contains("large content ends"));

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runs_the_complete_issue_workflow_without_javascript() {
    let fixture = Fixture::new("sha1");
    let database = fixture.instance.path().join(store::DATABASE_FILE);
    let token = "11".repeat(32);
    let csrf = "22".repeat(32);
    let session_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let csrf_hash: [u8; 32] = Sha256::digest(csrf.as_bytes()).into();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("read current time")
        .as_secs() as i64;
    let store = Store::open(&database).expect("open the issue fixture database");
    store
        .connection()
        .execute(
            "INSERT INTO web_session
             (session_hash, csrf_hash, account_id, created_at, expires_at)
             SELECT ?1, ?2, id, ?3, ?4 FROM account WHERE username = 'alice'",
            rusqlite::params![session_hash, csrf_hash, now, now + 3600,],
        )
        .expect("create a Web session");
    drop(store);

    let server = RunningWebServer::start_public(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        PublicWebConfig {
            instance_dir: fixture.instance.path().to_owned(),
            http_clone_base: "http://127.0.0.1".to_owned(),
            ssh_clone_base: "ssh://tit.example:2222".to_owned(),
            max_request_bytes: 1024 * 1024,
            max_connections: 1024,
        },
    )
    .await
    .expect("start the issue Web server");

    let anonymous = request(server.address(), "GET", "/alice/example/issues", &[], &[]);
    assert_eq!(anonymous.status, 200);
    assert_repository_navigation(&anonymous, "alice", "example");
    assert!(anonymous.text().contains("This repository has no issues."));
    assert!(!anonymous.text().contains("Create an issue</h2>"));

    let cookie = format!("tit-session={token}; tit-csrf={csrf}");
    let headers = [
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Cookie", cookie.as_str()),
    ];
    let create = form(&[
        ("csrf", &csrf),
        ("title", "Unsafe rendering check"),
        ("body", "**safe**\n\n<script>alert(1)</script>"),
    ]);
    let created = request(
        server.address(),
        "POST",
        "/alice/example/issues",
        &headers,
        create.as_bytes(),
    );
    assert_eq!(created.status, 303);
    assert_eq!(created.header("location"), "/alice/example/issues/1");

    let detail = request(
        server.address(),
        "GET",
        "/alice/example/issues/1",
        &[("Cookie", cookie.as_str())],
        &[],
    );
    assert_eq!(detail.status, 200);
    assert!(detail.text().contains("<strong>safe</strong>"));
    assert!(!detail.text().contains("<script>"));
    assert!(detail.text().contains("Add a comment"));
    assert!(detail.text().contains("Organize this issue"));

    let bad_csrf = form(&[("csrf", &"33".repeat(32)), ("state", "closed")]);
    assert_eq!(
        request(
            server.address(),
            "POST",
            "/alice/example/issues/1/state",
            &headers,
            bad_csrf.as_bytes(),
        )
        .status,
        403
    );
    for (path, fields) in [
        (
            "/alice/example/issues/1/comments",
            vec![
                ("csrf", csrf.as_str()),
                ("body", "A **comment** for @alice."),
            ],
        ),
        (
            "/alice/example/issues/1/edit",
            vec![
                ("csrf", csrf.as_str()),
                ("title", "Edited issue"),
                ("body", "Preserved _Markdown_."),
            ],
        ),
        (
            "/alice/example/issues/1/labels",
            vec![
                ("csrf", csrf.as_str()),
                ("label", "bug"),
                ("operation", "add"),
            ],
        ),
        (
            "/alice/example/issues/1/assignees",
            vec![
                ("csrf", csrf.as_str()),
                ("assignee", "alice"),
                ("operation", "add"),
            ],
        ),
        (
            "/alice/example/issues/1/state",
            vec![("csrf", csrf.as_str()), ("state", "closed")],
        ),
        (
            "/alice/example/issues/1/state",
            vec![("csrf", csrf.as_str()), ("state", "open")],
        ),
    ] {
        let response = request(
            server.address(),
            "POST",
            path,
            &headers,
            form(&fields).as_bytes(),
        );
        assert_eq!(response.status, 303, "issue mutation failed at {path}");
    }

    let final_page = request(
        server.address(),
        "GET",
        "/alice/example/issues/1",
        &[("Cookie", cookie.as_str())],
        &[],
    );
    let final_text = final_page.text();
    assert_eq!(final_page.status, 200);
    assert!(final_text.contains("#1 Edited issue"));
    assert!(final_text.contains("<em>Markdown</em>"));
    assert!(final_text.contains("<strong>comment</strong>"));
    assert!(final_text.contains("Labels: <span>bug</span>"));
    assert!(final_text.contains("Assignees: <span>alice</span>"));
    assert!(final_text.contains("issue-created"));
    assert!(final_text.contains("issue-reopened"));

    let anonymous_pull_requests =
        request(server.address(), "GET", "/alice/example/pulls", &[], &[]);
    assert_eq!(anonymous_pull_requests.status, 200);
    assert_repository_navigation(&anonymous_pull_requests, "alice", "example");
    assert!(
        anonymous_pull_requests
            .text()
            .contains("This repository has no pull requests.")
    );
    assert!(
        !anonymous_pull_requests
            .text()
            .contains("Open a pull request</h2>")
    );
    let open_pull_request = form(&[
        ("csrf", csrf.as_str()),
        ("title", "Review the feature"),
        ("body", "Keep **each revision**."),
        ("base-ref", "refs/heads/main"),
        ("head-ref", "refs/heads/feature"),
    ]);
    let opened_pull_request = request(
        server.address(),
        "POST",
        "/alice/example/pulls",
        &headers,
        open_pull_request.as_bytes(),
    );
    assert_eq!(opened_pull_request.status, 303);
    assert_eq!(
        opened_pull_request.header("location"),
        "/alice/example/pulls/1"
    );
    let pull_request_page = request(server.address(), "GET", "/alice/example/pulls/1", &[], &[]);
    assert_eq!(pull_request_page.status, 200);
    assert!(pull_request_page.text().contains("#1 Review the feature"));
    assert!(
        pull_request_page
            .text()
            .contains("<strong>each revision</strong>")
    );
    assert!(
        pull_request_page
            .text()
            .contains("git fetch origin refs/pull/1/head")
    );
    assert!(
        pull_request_page
            .text()
            .contains("Comparison for revision 1")
    );
    assert!(
        pull_request_page
            .text()
            .contains("Mergeability: already merged")
    );
    let worktree = fixture.instance.path().join("worktree");
    run(Command::new("git")
        .arg("-C")
        .arg(&worktree)
        .args(["switch", "-q", "feature"]));
    fs::write(worktree.join("pull-request.txt"), b"new revision\n")
        .expect("write a pull-request revision");
    commit_all(&worktree, "pull-request revision");
    let bare = fixture
        .instance
        .path()
        .join("repositories")
        .join(format!("{}.git", fixture.repository_id));
    run(Command::new("git")
        .arg("-C")
        .arg(&worktree)
        .args(["push", "-q"])
        .arg(&bare)
        .arg("feature"));
    let revision = form(&[("csrf", csrf.as_str())]);
    let revised_pull_request = request(
        server.address(),
        "POST",
        "/alice/example/pulls/1/revisions",
        &headers,
        revision.as_bytes(),
    );
    assert_eq!(revised_pull_request.status, 303);
    let revised_pull_request_page =
        request(server.address(), "GET", "/alice/example/pulls/1", &[], &[]);
    assert_eq!(
        revised_pull_request_page
            .text()
            .matches("recorded <code>")
            .count(),
        2
    );
    assert!(
        revised_pull_request_page
            .text()
            .contains("Comparison for revision 2")
    );
    assert!(
        revised_pull_request_page
            .text()
            .contains("pull-request.txt")
    );
    let first_revision = request(
        server.address(),
        "GET",
        "/alice/example/pulls/1?revision=1",
        &[],
        &[],
    );
    assert_eq!(first_revision.status, 200);
    assert!(first_revision.text().contains("Comparison for revision 1"));
    assert!(!first_revision.text().contains("pull-request.txt"));
    for fields in [
        vec![
            ("csrf", csrf.as_str()),
            ("revision", "2"),
            ("kind", "comment"),
            ("body", "A **general review**."),
            ("path-hex", ""),
            ("side", ""),
            ("line", ""),
        ],
        vec![
            ("csrf", csrf.as_str()),
            ("revision", "2"),
            ("kind", "approved"),
            ("body", ""),
            ("path-hex", ""),
            ("side", ""),
            ("line", ""),
        ],
        vec![
            ("csrf", csrf.as_str()),
            ("revision", "2"),
            ("kind", "line-comment"),
            ("body", "Review this line."),
            ("path-hex", "70756c6c2d726571756573742e747874"),
            ("side", "head"),
            ("line", "1"),
        ],
    ] {
        let response = request(
            server.address(),
            "POST",
            "/alice/example/pulls/1/reviews",
            &headers,
            form(&fields).as_bytes(),
        );
        assert_eq!(response.status, 303);
    }
    let reviewed = request(server.address(), "GET", "/alice/example/pulls/1", &[], &[]);
    assert!(reviewed.text().contains("<strong>general review</strong>"));
    assert!(reviewed.text().contains("pull-request-approved"));
    assert!(reviewed.text().contains("head line 1"));
    assert!(!reviewed.text().contains("<strong>Outdated</strong>"));

    fs::write(worktree.join("pull-request.txt"), b"later revision\n")
        .expect("write a later pull-request revision");
    commit_all(&worktree, "later pull-request revision");
    run(Command::new("git")
        .arg("-C")
        .arg(&worktree)
        .args(["push", "-q"])
        .arg(&bare)
        .arg("feature"));
    let revised_again = request(
        server.address(),
        "POST",
        "/alice/example/pulls/1/revisions",
        &headers,
        revision.as_bytes(),
    );
    assert_eq!(revised_again.status, 303);
    let outdated = request(server.address(), "GET", "/alice/example/pulls/1", &[], &[]);
    assert!(outdated.text().contains("<strong>Outdated</strong>"));
    let merge_page = request(
        server.address(),
        "GET",
        "/alice/example/pulls/1",
        &[("Cookie", cookie.as_str())],
        &[],
    );
    assert!(merge_page.text().contains("Fast-forward refs/heads/main"));
    let merge = request(
        server.address(),
        "POST",
        "/alice/example/pulls/1/merge",
        &headers,
        form(&[("csrf", csrf.as_str()), ("method", "fast-forward")]).as_bytes(),
    );
    assert_eq!(merge.status, 303);
    let merged = request(server.address(), "GET", "/alice/example/pulls/1", &[], &[]);
    assert!(merged.text().contains("merged · opened by alice"));
    assert!(merged.text().contains("pull-request-merged"));
    assert_eq!(
        rev_parse(&bare, "refs/heads/main"),
        rev_parse(&bare, "refs/heads/feature")
    );
    let search_page = request(server.address(), "GET", "/search", &[], &[]);
    assert_eq!(search_page.status, 200);
    assert!(
        search_page
            .text()
            .contains("Search repositories and issues")
    );
    let metadata_search = request(
        server.address(),
        "GET",
        "/search?q=Edited%20issue",
        &[],
        &[],
    );
    assert_eq!(metadata_search.status, 200);
    assert!(metadata_search.text().contains("/alice/example/issues/1"));
    assert_eq!(
        request(server.address(), "GET", "/search?q=", &[], &[]).status,
        400
    );
    let feed = request(server.address(), "GET", "/alice/example/atom.xml", &[], &[]);
    assert_eq!(feed.status, 200);
    assert!(feed.text().contains("alice reopened #1"));
    for (path, content_type) in [
        (
            "/alice/example/issues/atom.xml",
            "application/atom+xml; charset=utf-8",
        ),
        (
            "/alice/example/issues/rss.xml",
            "application/rss+xml; charset=utf-8",
        ),
    ] {
        let issue_feed = request(server.address(), "GET", path, &[], &[]);
        assert_eq!(issue_feed.status, 200);
        assert_eq!(issue_feed.header("content-type"), content_type);
        let parsed = feed_rs::parser::parse(issue_feed.body.as_slice())
            .expect("parse the public issue feed");
        assert!(!parsed.entries.is_empty());
        assert!(issue_feed.text().contains("reopened #1"));
        assert!(!issue_feed.text().contains("Repository imported"));
    }

    let anonymous_watch = request(server.address(), "GET", "/alice/example/watch", &[], &[]);
    assert_eq!(anonymous_watch.status, 200);
    assert_repository_navigation(&anonymous_watch, "alice", "example");
    assert!(
        anonymous_watch
            .text()
            .contains("Log in</a> to change watch preferences.")
    );
    let watch_page = request(
        server.address(),
        "GET",
        "/alice/example/watch",
        &[("Cookie", cookie.as_str())],
        &[],
    );
    assert_eq!(watch_page.status, 200);
    assert!(
        watch_page
            .text()
            .contains("You do not watch this repository.")
    );
    let everything = form(&[
        ("csrf", csrf.as_str()),
        ("pushes", "1"),
        ("issues", "1"),
        ("pull-requests", "1"),
    ]);
    let watched = request(
        server.address(),
        "POST",
        "/alice/example/watch",
        &headers,
        everything.as_bytes(),
    );
    assert_eq!(watched.status, 303);
    assert_eq!(watched.header("location"), "/alice/example/watch");
    let selected = request(
        server.address(),
        "GET",
        "/alice/example/watch",
        &[("Cookie", cookie.as_str())],
        &[],
    );
    assert!(
        selected
            .text()
            .contains("You watch selected activity in this repository.")
    );
    assert_eq!(selected.text().matches("value=\"1\" selected").count(), 3);

    let feed_tokens = request(
        server.address(),
        "GET",
        "/feeds",
        &[("Cookie", cookie.as_str())],
        &[],
    );
    assert_eq!(feed_tokens.status, 200);
    assert!(feed_tokens.text().contains("Feed URLs are credentials."));
    let issue_repository_token = form(&[
        ("csrf", csrf.as_str()),
        ("scope", "repository"),
        ("owner", "alice"),
        ("repository", "example"),
    ]);
    let issued = request(
        server.address(),
        "POST",
        "/feeds/tokens",
        &headers,
        issue_repository_token.as_bytes(),
    );
    assert_eq!(issued.status, 201);
    assert!(issued.text().contains("tit will not show them again."));
    let private_token = extract_feed_token(issued.text());
    let private_path = format!("/feeds/{private_token}/atom.xml");
    let private_feed = request(server.address(), "GET", &private_path, &[], &[]);
    assert_eq!(private_feed.status, 200);
    assert_eq!(private_feed.header("cache-control"), "private, no-store");
    assert_eq!(private_feed.header("referrer-policy"), "no-referrer");
    assert!(private_feed.text().contains("alice/example"));
    let private_hash: [u8; 32] = Sha256::digest(private_token.as_bytes()).into();
    let token_store = Store::open(&database).expect("open the feed token database");
    let (private_id, stored_hash): (String, Vec<u8>) = token_store
        .connection()
        .query_row(
            "SELECT id, token_hash FROM feed_token
             WHERE scope = 'repository' AND revoked_at IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read the stored feed token hash");
    assert_eq!(stored_hash, private_hash);
    assert_ne!(stored_hash, private_token.as_bytes());
    drop(token_store);
    let hidden_token = request(
        server.address(),
        "GET",
        "/feeds",
        &[("Cookie", cookie.as_str())],
        &[],
    );
    assert!(!hidden_token.text().contains(&private_token));

    let private_store = Store::open(&database).expect("open the private feed database");
    private_store
        .connection()
        .execute(
            "UPDATE repository SET visibility = 'private' WHERE slug = 'example'",
            [],
        )
        .expect("make the feed repository private");
    drop(private_store);
    assert_eq!(
        request(
            server.address(),
            "GET",
            "/alice/example/issues/atom.xml",
            &[],
            &[],
        )
        .status,
        404
    );
    let anonymous_private_search = request(
        server.address(),
        "GET",
        "/search?q=Edited%20issue",
        &[],
        &[],
    );
    assert!(
        anonymous_private_search
            .text()
            .contains("No repository or issue matched")
    );
    let owner_private_search = request(
        server.address(),
        "GET",
        "/search?q=Edited%20issue",
        &[("Cookie", cookie.as_str())],
        &[],
    );
    assert!(
        owner_private_search
            .text()
            .contains("/alice/example/issues/1")
    );
    assert_eq!(
        request(server.address(), "GET", &private_path, &[], &[]).status,
        200
    );

    let rotate = form(&[("csrf", csrf.as_str())]);
    let rotated = request(
        server.address(),
        "POST",
        &format!("/feeds/tokens/{private_id}/rotate"),
        &headers,
        rotate.as_bytes(),
    );
    assert_eq!(rotated.status, 201);
    let rotated_token = extract_feed_token(rotated.text());
    assert_ne!(rotated_token, private_token);
    assert_eq!(
        request(server.address(), "GET", &private_path, &[], &[]).status,
        404
    );
    let rotated_path = format!("/feeds/{rotated_token}/rss.xml");
    assert_eq!(
        request(server.address(), "GET", &rotated_path, &[], &[]).status,
        200
    );
    let rotated_hash: [u8; 32] = Sha256::digest(rotated_token.as_bytes()).into();
    let rotated_store = Store::open(&database).expect("open the rotated feed database");
    let rotated_id: String = rotated_store
        .connection()
        .query_row(
            "SELECT id FROM feed_token WHERE token_hash = ?1 AND revoked_at IS NULL",
            [rotated_hash.as_slice()],
            |row| row.get(0),
        )
        .expect("read the rotated feed token ID");
    drop(rotated_store);
    let revoked = request(
        server.address(),
        "POST",
        &format!("/feeds/tokens/{rotated_id}/revoke"),
        &headers,
        rotate.as_bytes(),
    );
    assert_eq!(revoked.status, 303);
    assert_eq!(
        request(server.address(), "GET", &rotated_path, &[], &[]).status,
        404
    );

    for (scope, expected, excluded, format) in [
        (
            "watched",
            "commented on #1",
            "no excluded event",
            "atom.xml",
        ),
        (
            "assignments",
            "assigned alice on #1",
            "commented on #1",
            "rss.xml",
        ),
        (
            "mentions",
            "commented on #1",
            "assigned alice on #1",
            "atom.xml",
        ),
    ] {
        let body = form(&[
            ("csrf", csrf.as_str()),
            ("scope", scope),
            ("owner", ""),
            ("repository", ""),
        ]);
        let issued = request(
            server.address(),
            "POST",
            "/feeds/tokens",
            &headers,
            body.as_bytes(),
        );
        assert_eq!(issued.status, 201, "did not issue the {scope} token");
        let token = extract_feed_token(issued.text());
        let response = request(
            server.address(),
            "GET",
            &format!("/feeds/{token}/{format}"),
            &[],
            &[],
        );
        assert_eq!(response.status, 200, "did not read the {scope} feed");
        feed_rs::parser::parse(response.body.as_slice())
            .unwrap_or_else(|_| panic!("parse the {scope} feed"));
        assert!(response.text().contains(expected), "wrong {scope} feed");
        if excluded != "no excluded event" {
            assert!(
                !response.text().contains(excluded),
                "the {scope} token escaped its scope"
            );
        }
    }

    let none = form(&[
        ("csrf", csrf.as_str()),
        ("pushes", "0"),
        ("issues", "0"),
        ("pull-requests", "0"),
    ]);
    assert_eq!(
        request(
            server.address(),
            "POST",
            "/alice/example/watch",
            &headers,
            none.as_bytes(),
        )
        .status,
        303
    );
    assert_eq!(
        Store::open(&database)
            .expect("reopen the watch database")
            .connection()
            .query_row("SELECT count(*) FROM watch", [], |row| row.get::<_, i64>(0))
            .expect("count cleared watches"),
        0
    );

    server.shutdown().await.expect("stop the issue Web server");
}

fn form(fields: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(fields.iter().copied());
    serializer.finish()
}

fn extract_feed_token(body: &str) -> String {
    let marker = "/feeds/";
    let start = body.find(marker).expect("find a feed URL") + marker.len();
    let token = body[start..].split('/').next().expect("read a feed token");
    assert_eq!(token.len(), 64);
    assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    token.to_owned()
}

fn assert_hidden(address: SocketAddr, head: &str) {
    for route in [
        "/alice/example".to_owned(),
        format!("/alice/example/raw/{head}/README.md"),
        "/alice/example/atom.xml".to_owned(),
        "/alice/example/rss.xml".to_owned(),
        "/alice/example/search?q=text".to_owned(),
        "/alice/example/info/refs?service=git-upload-pack".to_owned(),
    ] {
        let response = request(address, "GET", &route, &[], &[]);
        assert_eq!(response.status, 404, "repository was visible at {route}");
    }
}

struct Fixture {
    instance: TempDir,
    repository_id: String,
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
        run(Command::new("git").arg("-C").arg(&worktree).args([
            "config",
            "commit.gpgsign",
            "false",
        ]));
        fs::write(
            worktree.join("README.md"),
            b"# tit fixture\n\n**safe** and `<safe>`\n\n[guide](docs/guide.md) [bad](javascript:alert(1))\n\n![tracker](https://tracker.example/pixel)\n\n<script>alert(2)</script>\n",
        )
        .expect("write the README");
        fs::create_dir(worktree.join("nested")).expect("create a nested directory");
        fs::write(worktree.join("nested/file.txt"), b"first line\n").expect("write the text file");
        fs::write(worktree.join("binary.dat"), b"binary\0content").expect("write the binary file");
        let mut large = vec![b'x'; 2 * 1024 * 1024];
        let prefix = b"large content starts\n";
        large[..prefix.len()].copy_from_slice(prefix);
        let suffix = b"\nlarge content ends\n";
        let suffix_start = large.len() - suffix.len();
        large[suffix_start..].copy_from_slice(suffix);
        fs::write(worktree.join("large.txt"), large).expect("write the large file");
        fs::write(
            worktree.join("<img src=x onerror=alert(4)>.txt"),
            b"escaped path\n",
        )
        .expect("write the hostile path");
        fs::write(worktree.join("non-å.txt"), b"non-UTF-8 path\n")
            .expect("write the percent-encoded path");
        fs::write(worktree.join("malformed.txt"), b"start \xff needle\n")
            .expect("write malformed UTF-8 content");
        commit_all(&worktree, "first commit");
        let parent = rev_parse(&worktree, "HEAD");
        for index in 1..=10 {
            commit_empty(&worktree, &format!("intermediate commit {index}"));
        }
        fs::write(
            worktree.join("nested/file.txt"),
            b"first line\nsecond line\n",
        )
        .expect("update the text file");
        commit_all(&worktree, "<script>alert(3)</script>");
        let head = rev_parse(&worktree, "HEAD");
        run(Command::new("git")
            .arg("-C")
            .arg(&worktree)
            .args(["branch", "feature"]));

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
            .args(["main", "feature"]));

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
                origin: RepositoryOrigin::Imported,
                initial_references: &[],
                actor: "admin-cli",
                correlation_id: "test-import",
            })
            .expect("create the repository record");
        store
            .create_repository(&NewRepository {
                id: "33333333333333333333333333333333",
                owner: "alice",
                slug: "empty",
                object_format: format,
                created_at: 2,
                origin: RepositoryOrigin::Created,
                initial_references: &[],
                actor: "admin-cli",
                correlation_id: "test-create",
            })
            .expect("create the empty repository record");
        drop(store);

        Self {
            instance,
            repository_id: id.to_owned(),
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

fn commit_empty(worktree: &Path, message: &str) {
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["commit", "-q", "--allow-empty", "-m", message])
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
        .expect("write HTTP request headers");
    if let Err(error) = stream.write_all(body)
        && !matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        )
    {
        panic!("write an HTTP request: {error}");
    }
    let mut response = Vec::new();
    if let Err(error) = stream.read_to_end(&mut response)
        && error.kind() != std::io::ErrorKind::ConnectionReset
    {
        panic!("read an HTTP response: {error}");
    }
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

fn assert_repository_navigation(response: &HttpResponse, owner: &str, repository: &str) {
    let text = response.text();
    for suffix in [
        "",
        "/refs",
        "/issues",
        "/pulls",
        "/watch",
        "/atom.xml",
        "/rss.xml",
        "/search",
    ] {
        let link = format!("/{owner}/{repository}{suffix}");
        assert!(
            text.contains(&format!("href=\"{link}\"")),
            "repository navigation is missing {link}"
        );
    }
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
