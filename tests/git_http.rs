#[path = "../src/git/http.rs"]
mod http;
#[allow(dead_code, reason = "the HTTP test does not run maintenance")]
#[path = "../src/maintenance.rs"]
mod maintenance;
#[allow(
    dead_code,
    reason = "the HTTP test does not use each shared protocol API"
)]
#[path = "../src/git/packetline.rs"]
mod packetline;
#[allow(dead_code, reason = "the HTTP test does not use repository policy")]
#[path = "../src/policy.rs"]
mod policy;
#[allow(
    dead_code,
    reason = "the HTTP test does not inspect repository internals"
)]
#[path = "../src/git/repository.rs"]
mod repository;
#[allow(dead_code, reason = "the HTTP test does not use the intent store")]
#[path = "../src/store/mod.rs"]
mod store;
#[allow(
    dead_code,
    reason = "the HTTP test uses transport resolution through HTTP"
)]
#[path = "../src/git/transport.rs"]
mod transport;
#[allow(dead_code, reason = "the HTTP test uses upload-pack through HTTP")]
#[path = "../src/git/upload_pack.rs"]
mod upload_pack;

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use http::RunningGitHttpServer;
use tempfile::TempDir;
use transport::GitRepositories;
use upload_pack::{ProtocolVersion, UploadPack, UploadPackError};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stock_git_clones_and_fetches_both_hash_formats_over_smart_http() {
    for format in ["sha1", "sha256"] {
        let directory = TempDir::new().expect("create a Git HTTP fixture directory");
        let repositories_root = directory.path().join("repositories");
        let bare = repositories_root.join("alice/example.git");
        let worktree = directory.path().join("worktree");
        create_fixture(&worktree, &bare, format);
        let repositories =
            GitRepositories::new(&repositories_root).expect("open the repository root");
        let server =
            RunningGitHttpServer::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), repositories)
                .await
                .expect("start the Git HTTP server");

        let versions: &[&str] = if format == "sha1" {
            &["0", "1", "2"]
        } else {
            &["1", "2"]
        };
        for version in versions {
            let clone = directory.path().join(format!("clone-v{version}"));
            let url = format!("http://{}/alice/example", server.address());
            run(Command::new("git")
                .args(["-c", &format!("protocol.version={version}"), "clone", "-q"])
                .arg(&url)
                .arg(&clone));
            assert_eq!(head(&clone), head(&worktree));
            assert_eq!(
                rev_parse(&clone, "refs/remotes/origin/feature"),
                rev_parse(&worktree, "refs/heads/feature")
            );
            assert_eq!(
                rev_parse(&clone, "refs/tags/v1^{}"),
                rev_parse(&worktree, "refs/tags/v1^{}")
            );
            assert_eq!(
                fs::read(clone.join("non-ascii-\u{00e5}.txt")).expect("read a cloned file"),
                b"first payload\n"
            );
            assert_eq!(
                fs::metadata(clone.join("large-copy.bin"))
                    .expect("inspect a cloned large blob")
                    .len(),
                2 * 1024 * 1024
            );

            append_commit(&worktree, format!("fetch-v{version}.txt"));
            run(Command::new("git").arg("-C").arg(&worktree).args([
                "push",
                "-q",
                &bare.to_string_lossy(),
                "main",
            ]));
            run(Command::new("git").arg("-C").arg(&clone).args([
                "-c",
                &format!("protocol.version={version}"),
                "fetch",
                "-q",
            ]));
            assert_eq!(
                rev_parse(&clone, "refs/remotes/origin/main"),
                head(&worktree)
            );
        }

        server.shutdown().await.expect("stop the Git HTTP server");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_invalid_http_routes_and_oversized_requests() {
    let directory = TempDir::new().expect("create a Git HTTP fixture directory");
    let repositories_root = directory.path().join("repositories");
    fs::create_dir_all(&repositories_root).expect("create the repository root");
    let repository = repositories_root.join("alice/example.git");
    fs::create_dir_all(repository.parent().expect("a repository owner directory"))
        .expect("create the repository owner directory");
    run(Command::new("git")
        .args(["init", "-q", "--bare"])
        .arg(&repository));
    let repositories = GitRepositories::new(&repositories_root).expect("open the repository root");
    let server =
        RunningGitHttpServer::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), repositories)
            .await
            .expect("start the Git HTTP server");

    let missing = Command::new("git")
        .args(["ls-remote", &format!("http://{}/../etc", server.address())])
        .output()
        .expect("run stock Git against an invalid route");
    assert!(!missing.status.success());

    let malformed = raw_http_request(
        server.address(),
        "/alice/example/git-upload-pack",
        "application/x-git-upload-pack-request",
        Some("version=2"),
        b"zzzz",
    );
    assert!(malformed.starts_with(b"HTTP/1.1 400"));

    let wrong_service = raw_http_get(
        server.address(),
        "/alice/example/info/refs?service=git-receive-pack",
    );
    assert!(wrong_service.starts_with(b"HTTP/1.1 400"));

    let wrong_content_type = raw_http_request(
        server.address(),
        "/alice/example/git-upload-pack",
        "text/plain",
        Some("version=2"),
        b"0000",
    );
    assert!(wrong_content_type.starts_with(b"HTTP/1.1 415"));

    let wrong_version = raw_http_request(
        server.address(),
        "/alice/example/git-upload-pack",
        "application/x-git-upload-pack-request",
        Some("version=2:extra"),
        b"0000",
    );
    assert!(wrong_version.starts_with(b"HTTP/1.1 400"));

    let oversized = raw_http_request(
        server.address(),
        "/alice/example/git-upload-pack",
        "application/x-git-upload-pack-request",
        Some("version=2"),
        &vec![b'0'; packetline::MAX_REQUEST_BYTES + 1],
    );
    assert!(oversized.starts_with(b"HTTP/1.1 413"));
    server.shutdown().await.expect("stop the Git HTTP server");
}

#[test]
fn upload_pack_deduplicates_and_limits_negotiation_ids() {
    let directory = TempDir::new().expect("create an upload-pack fixture directory");
    let worktree = directory.path().join("worktree");
    let bare = directory.path().join("repository.git");
    create_fixture(&worktree, &bare, "sha1");
    let head = rev_parse(&bare, "refs/heads/main");
    let service = UploadPack::open(&bare).expect("open upload-pack");

    let mut duplicate = Vec::new();
    for _ in 0..512 {
        packetline::encode_data(format!("want {head}\n").as_bytes(), &mut duplicate)
            .expect("encode a duplicate want");
    }
    packetline::encode_data(b"done\n", &mut duplicate).expect("encode done");
    packetline::encode_flush(&mut duplicate);
    let response = service
        .respond(ProtocolVersion::V1, &duplicate)
        .expect("deduplicate negotiation IDs");
    assert!(response.windows(4).any(|window| window == b"PACK"));

    let mut excessive = Vec::new();
    for value in 1_u64..=257 {
        packetline::encode_data(format!("want {value:040x}\n").as_bytes(), &mut excessive)
            .expect("encode a distinct want");
    }
    packetline::encode_data(b"done\n", &mut excessive).expect("encode done");
    packetline::encode_flush(&mut excessive);
    assert!(matches!(
        service.respond(ProtocolVersion::V1, &excessive),
        Err(UploadPackError::NegotiationLimit)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stock_git_clones_empty_repositories_for_both_hash_formats() {
    for format in ["sha1", "sha256"] {
        let directory = TempDir::new().expect("create an empty repository fixture directory");
        let repositories_root = directory.path().join("repositories");
        let bare = repositories_root.join("alice/empty.git");
        fs::create_dir_all(bare.parent().expect("an empty repository parent"))
            .expect("create an empty repository owner directory");
        run(Command::new("git")
            .args(["init", "-q", "--bare", "--object-format", format])
            .arg(&bare));
        let repositories =
            GitRepositories::new(&repositories_root).expect("open the repository root");
        let server =
            RunningGitHttpServer::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), repositories)
                .await
                .expect("start the Git HTTP server");
        let clone = directory.path().join("clone");
        run(Command::new("git")
            .args(["-c", "protocol.version=2", "clone", "-q"])
            .arg(format!("http://{}/alice/empty", server.address()))
            .arg(&clone));
        let head = Command::new("git")
            .arg("-C")
            .arg(&clone)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("inspect the empty clone");
        assert!(!head.status.success());
        server.shutdown().await.expect("stop the Git HTTP server");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_process_does_not_invoke_git() {
    const CHILD_VARIABLE: &str = "TIT_M1C_INSTRUMENTED_CHILD";
    const ROOT_VARIABLE: &str = "TIT_M1C_REPOSITORY_ROOT";
    const GIT_VARIABLE: &str = "TIT_M1C_GIT_BINARY";
    const PATH_VARIABLE: &str = "TIT_M1C_DRIVER_PATH";
    const EXEC_PATH_VARIABLE: &str = "TIT_M1C_GIT_EXEC_PATH";

    if std::env::var_os(CHILD_VARIABLE).is_some() {
        let root = PathBuf::from(std::env::var_os(ROOT_VARIABLE).expect("a repository root"));
        let git = PathBuf::from(std::env::var_os(GIT_VARIABLE).expect("a stock Git binary"));
        let driver_path = std::env::var_os(PATH_VARIABLE).expect("a stock Git PATH");
        let git_exec_path = std::env::var_os(EXEC_PATH_VARIABLE).expect("a stock Git exec path");
        let repositories = GitRepositories::new(&root).expect("open the repository root");
        let server =
            RunningGitHttpServer::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), repositories)
                .await
                .expect("start the instrumented Git HTTP server");
        let clone = root
            .parent()
            .expect("a fixture directory")
            .join("instrumented-clone");
        let output = Command::new(git)
            .args(["-c", "protocol.version=2", "clone", "-q"])
            .arg(format!("http://{}/alice/example", server.address()))
            .arg(clone)
            .env("PATH", driver_path)
            .env("GIT_EXEC_PATH", git_exec_path)
            .output()
            .expect("run the instrumented stock Git client");
        assert!(
            output.status.success(),
            "instrumented stock Git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        server.shutdown().await.expect("stop the Git HTTP server");
        return;
    }

    let directory = TempDir::new().expect("create an instrumentation fixture directory");
    let repositories_root = directory.path().join("repositories");
    create_fixture(
        &directory.path().join("worktree"),
        &repositories_root.join("alice/example.git"),
        "sha1",
    );
    let marker = directory.path().join("git-was-invoked");
    let sentinel_directory = directory.path().join("sentinel-path");
    fs::create_dir(&sentinel_directory).expect("create the sentinel PATH");
    let sentinel = sentinel_directory.join("git");
    fs::write(
        &sentinel,
        format!(
            "#!/bin/sh\nprintf invoked > '{}'\nexit 97\n",
            marker.display()
        ),
    )
    .expect("write the Git sentinel");
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o700))
        .expect("make the Git sentinel executable");

    let git_binary = command_output(Command::new("which").arg("git"));
    let git_exec_path = command_output(Command::new("git").arg("--exec-path"));
    let driver_path = std::env::var_os("PATH").expect("the test driver PATH");
    let output = Command::new(std::env::current_exe().expect("find the test executable"))
        .args([
            "--exact",
            "server_process_does_not_invoke_git",
            "--nocapture",
        ])
        .env(CHILD_VARIABLE, "1")
        .env(ROOT_VARIABLE, &repositories_root)
        .env(GIT_VARIABLE, git_binary.trim())
        .env(PATH_VARIABLE, driver_path)
        .env(EXEC_PATH_VARIABLE, git_exec_path.trim())
        .env("PATH", &sentinel_directory)
        .output()
        .expect("run the instrumented server process");
    assert!(
        output.status.success(),
        "instrumented server process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "the server process invoked Git");
}

fn command_output(command: &mut Command) -> String {
    let output = run(command);
    String::from_utf8(output.stdout)
        .expect("read command output")
        .trim()
        .to_owned()
}

fn raw_http_request(
    address: SocketAddr,
    path: &str,
    content_type: &str,
    git_protocol: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut stream = std::net::TcpStream::connect(address).expect("connect to the Git HTTP server");
    let protocol_header = git_protocol
        .map(|value| format!("Git-Protocol: {value}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: {content_type}\r\n{protocol_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .expect("write HTTP request headers");
    stream.write_all(body).expect("write HTTP request body");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read the Git HTTP response");
    response
}

fn raw_http_get(address: SocketAddr, path: &str) -> Vec<u8> {
    let mut stream = std::net::TcpStream::connect(address).expect("connect to the Git HTTP server");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .expect("write HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read the Git HTTP response");
    response
}

fn create_fixture(worktree: &Path, bare: &Path, format: &str) {
    fs::create_dir_all(bare.parent().expect("a bare repository parent"))
        .expect("create the repository owner directory");
    run(Command::new("git")
        .args(["init", "-q", "--object-format", format, "-b", "main"])
        .arg(worktree));
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["config", "user.name", "Tit Test"]));
    run(Command::new("git").arg("-C").arg(worktree).args([
        "config",
        "user.email",
        "tit@example.invalid",
    ]));
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["config", "commit.gpgsign", "false"]));
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["config", "tag.gpgsign", "false"]));
    fs::write(worktree.join("non-ascii-\u{00e5}.txt"), b"first payload\n")
        .expect("write the first fixture file");
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["add", "."]));
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["commit", "-q", "-m", "first commit"]));
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["tag", "-a", "v1", "-m", "version one"]));
    let large = vec![b'a'; 2 * 1024 * 1024];
    let mut similar = large.clone();
    similar[1024 * 1024..1024 * 1024 + 16].copy_from_slice(b"different bytes!");
    fs::write(worktree.join("large-original.bin"), large).expect("write a large fixture blob");
    fs::write(worktree.join("large-copy.bin"), similar).expect("write a similar fixture blob");
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["add", "."]));
    run(Command::new("git").arg("-C").arg(worktree).args([
        "commit",
        "-q",
        "-m",
        "add large similar blobs",
    ]));
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["branch", "feature", "HEAD~1"]));
    run(Command::new("git")
        .args(["clone", "-q", "--bare"])
        .arg(worktree)
        .arg(bare));
    run(Command::new("git")
        .arg("--git-dir")
        .arg(bare)
        .args(["gc", "--aggressive", "--prune=now"]));
    assert_has_delta(bare);
}

fn assert_has_delta(repository: &Path) {
    let index = fs::read_dir(repository.join("objects/pack"))
        .expect("read the pack directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|extension| extension == "idx"))
        .expect("find a pack index");
    let output = run(Command::new("git")
        .arg("--git-dir")
        .arg(repository)
        .args(["verify-pack", "-v"])
        .arg(index));
    assert!(
        String::from_utf8(output.stdout)
            .expect("read verify-pack output")
            .lines()
            .any(|line| line.split_whitespace().count() >= 7),
        "the fixture pack does not contain a delta"
    );
}

fn append_commit(worktree: &Path, filename: String) {
    fs::write(
        worktree.join(&filename),
        format!("payload for {filename}\n"),
    )
    .expect("write a fetch fixture file");
    run(Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["add", &filename]));
    run(Command::new("git").arg("-C").arg(worktree).args([
        "commit",
        "-q",
        "-m",
        &format!("add {filename}"),
    ]));
}

fn head(path: &Path) -> String {
    rev_parse(path, "HEAD")
}

fn rev_parse(path: &Path, name: &str) -> String {
    let output = run(Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", name]));
    String::from_utf8(output.stdout)
        .expect("read an object ID")
        .trim()
        .to_owned()
}

fn run(command: &mut Command) -> std::process::Output {
    let output = command.output().expect("run stock Git");
    assert!(
        output.status.success(),
        "stock Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
