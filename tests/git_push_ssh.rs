#[allow(
    dead_code,
    reason = "the SSH push test does not use each authentication API"
)]
#[path = "../src/auth.rs"]
mod auth;
#[allow(dead_code, reason = "the SSH push test does not use domain models")]
#[path = "../src/domain/mod.rs"]
mod domain;
#[allow(
    dead_code,
    reason = "the SSH push test does not use each Git service API"
)]
#[path = "../src/git/mod.rs"]
mod git;
#[allow(dead_code, reason = "the SSH push test does not use issue commands")]
#[path = "../src/issue.rs"]
mod issue;
#[allow(dead_code, reason = "the SSH push test does not run maintenance")]
#[path = "../src/maintenance.rs"]
mod maintenance;
#[allow(dead_code, reason = "the SSH push test does not use repository policy")]
#[path = "../src/policy.rs"]
mod policy;
#[path = "../src/rate_limit.rs"]
mod rate_limit;
#[allow(dead_code, reason = "the SSH push test does not create repositories")]
#[path = "../src/repository.rs"]
mod repository;
#[allow(
    dead_code,
    reason = "the SSH push test does not inspect the request audit"
)]
#[path = "../src/ssh.rs"]
mod ssh;
#[allow(dead_code, reason = "the SSH push test does not use each store API")]
#[path = "../src/store/mod.rs"]
mod store;

use std::env;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use auth::SshPublicKey;
use git::transport::GitRepositories;
use ssh::RunningSshServer;
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stock_git_creates_and_updates_branches_for_both_hash_formats_over_ssh() {
    for format in ["sha1", "sha256"] {
        let directory = TempDir::new().expect("create an SSH push fixture directory");
        let repositories_root = directory.path().join("repositories");
        let bare = repositories_root.join("alice/example.git");
        let worktree = directory.path().join("worktree");
        fs::create_dir_all(bare.parent().expect("a bare repository parent"))
            .expect("create a repository owner directory");
        run(Command::new("git")
            .args(["init", "-q", "--bare", "--object-format", format])
            .arg(&bare));
        create_worktree(&worktree, format);

        let private_key = directory.path().join("id_ed25519");
        create_key(&private_key);
        let key = parse_key(&private_key);
        let reader_private_key = directory.path().join("reader_ed25519");
        create_key(&reader_private_key);
        let reader_key = parse_key(&reader_private_key);
        let database = directory.path().join("tit.db");
        store::Store::open(&database).expect("create the intent store");
        let repositories = GitRepositories::new_with_pushes(&repositories_root, &database)
            .expect("open the repository root");
        let server = RunningSshServer::start_with_git_writes(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &[key.clone(), reader_key],
            std::slice::from_ref(&key),
            repositories,
        )
        .await
        .expect("start the SSH Git server");
        let url = format!(
            "ssh://ignored@{}:{}/alice/example",
            server.address().ip(),
            server.address().port()
        );

        push(&worktree, &private_key, &url, &["main"]);
        assert_eq!(rev_parse(&bare, "refs/heads/main"), head(&worktree));

        fs::write(worktree.join("second.txt"), b"second commit\n").expect("write a second file");
        run(Command::new("git")
            .arg("-C")
            .arg(&worktree)
            .args(["add", "."]));
        run(Command::new("git").arg("-C").arg(&worktree).args([
            "commit",
            "-q",
            "-m",
            "second commit",
        ]));
        push(&worktree, &private_key, &url, &["main"]);
        assert_eq!(rev_parse(&bare, "refs/heads/main"), head(&worktree));

        run(Command::new("git")
            .arg("-C")
            .arg(&worktree)
            .args(["branch", "feature"]));
        run(Command::new("git")
            .arg("-C")
            .arg(&worktree)
            .args(["tag", "v1"]));
        push(
            &worktree,
            &private_key,
            &url,
            &["--atomic", "feature", "v1"],
        );
        assert_eq!(
            rev_parse(&bare, "refs/heads/feature"),
            rev_parse(&worktree, "refs/heads/feature")
        );
        assert_eq!(
            rev_parse(&bare, "refs/tags/v1"),
            rev_parse(&worktree, "refs/tags/v1")
        );
        push(
            &worktree,
            &private_key,
            &url,
            &["--delete", "feature", "v1"],
        );
        assert_missing_ref(&bare, "refs/heads/feature");
        assert_missing_ref(&bare, "refs/tags/v1");

        let blob = run(Command::new("git").arg("-C").arg(&worktree).args([
            "hash-object",
            "-w",
            "second.txt",
        ]));
        let blob = String::from_utf8(blob.stdout)
            .expect("read a blob ID")
            .trim()
            .to_owned();
        run(Command::new("git").arg("-C").arg(&worktree).args([
            "update-ref",
            "refs/tit/blob",
            &blob,
        ]));
        let invalid_branch = push_result(
            &worktree,
            &private_key,
            &url,
            &["refs/tit/blob:refs/heads/not-a-commit"],
        );
        assert!(
            !invalid_branch.status.success()
                && String::from_utf8_lossy(&invalid_branch.stderr)
                    .contains("branch target is not a commit"),
            "the server did not reject a branch that targets a blob: {}",
            String::from_utf8_lossy(&invalid_branch.stderr)
        );
        assert_missing_ref(&bare, "refs/heads/not-a-commit");

        let accepted_head = rev_parse(&bare, "refs/heads/main");
        run(Command::new("git")
            .arg("-C")
            .arg(&worktree)
            .args(["reset", "--hard", "HEAD~1"]));
        fs::write(worktree.join("rejected.txt"), b"rejected history\n")
            .expect("write a rejected file");
        run(Command::new("git")
            .arg("-C")
            .arg(&worktree)
            .args(["add", "."]));
        run(Command::new("git").arg("-C").arg(&worktree).args([
            "commit",
            "-q",
            "-m",
            "rejected history",
        ]));
        let rejected_object = head(&worktree);
        let rejected = push_result(&worktree, &private_key, &url, &["--force", "main"]);
        assert!(
            !rejected.status.success(),
            "the server accepted a non-fast-forward push"
        );
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains("non-fast-forward"),
            "the server did not return an accurate per-ref status: {}",
            String::from_utf8_lossy(&rejected.stderr)
        );
        assert_eq!(rev_parse(&bare, "refs/heads/main"), accepted_head);
        assert_missing_object(&bare, &rejected_object);
        let atomic_rejection = push_result(
            &worktree,
            &private_key,
            &url,
            &[
                "--atomic",
                "--force",
                "main",
                "HEAD:refs/heads/must-not-exist",
            ],
        );
        assert!(
            !atomic_rejection.status.success(),
            "the server partially accepted an invalid atomic push"
        );
        assert_missing_ref(&bare, "refs/heads/must-not-exist");
        assert_eq!(rev_parse(&bare, "refs/heads/main"), accepted_head);
        assert!(
            store::Store::open(&database)
                .expect("open the intent store after rejection")
                .incomplete_git_intents()
                .expect("list incomplete rejected pushes")
                .is_empty(),
            "a rejected push left an incomplete intent"
        );
        assert_eq!(
            fs::read_dir(bare.join("objects/tit-quarantine"))
                .map(|entries| entries.count())
                .unwrap_or(0),
            0,
            "a rejected push left a quarantine directory"
        );

        let unauthorized = push_result(
            &worktree,
            &reader_private_key,
            &url,
            &["HEAD:refs/heads/unauthorized"],
        );
        assert!(
            !unauthorized.status.success(),
            "the server accepted a push from a read-only key"
        );
        assert_missing_ref(&bare, "refs/heads/unauthorized");

        server.shutdown().await.expect("stop the SSH Git server");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn git_push_crash_child() {
    let Some(mode) = env::var_os("TIT_M1D_CHILD_MODE") else {
        return;
    };
    let repositories_root = required_path("TIT_M1D_REPOSITORIES");
    let database = required_path("TIT_M1D_DATABASE");
    let worktree = required_path("TIT_M1D_WORKTREE");
    let private_key = required_path("TIT_M1D_PRIVATE_KEY");
    let key = parse_key(&private_key);
    let repositories = GitRepositories::new_with_pushes(&repositories_root, &database)
        .expect("open the crash-test repository root");
    let server = RunningSshServer::start_with_git_writes(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        std::slice::from_ref(&key),
        std::slice::from_ref(&key),
        repositories,
    )
    .await
    .expect("start the crash-test SSH server");
    let url = format!(
        "ssh://ignored@{}:{}/alice/example",
        server.address().ip(),
        server.address().port()
    );
    let output = push_result(&worktree, &private_key, &url, &["main"]);
    panic!(
        "the {mode:?} crash hook did not stop receive-pack: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn reconciles_process_termination_at_each_cross_store_boundary() {
    for boundary in ["intent", "objects", "refs", "completed"] {
        let directory = TempDir::new().expect("create a recovery fixture directory");
        let repositories_root = directory.path().join("repositories");
        let bare = repositories_root.join("alice/example.git");
        let worktree = directory.path().join("worktree");
        fs::create_dir_all(bare.parent().expect("a bare repository parent"))
            .expect("create a repository owner directory");
        run(Command::new("git")
            .args(["init", "-q", "--bare", "--object-format", "sha1"])
            .arg(&bare));
        create_worktree(&worktree, "sha1");
        let proposed = head(&worktree);
        let private_key = directory.path().join("id_ed25519");
        create_key(&private_key);
        let database = directory.path().join("tit.db");
        store::Store::open(&database).expect("create the intent store");
        let ready = directory.path().join("ready");

        let child = spawn_push_crash_child(
            boundary,
            &repositories_root,
            &database,
            &worktree,
            &private_key,
            &ready,
        );
        kill_after_ready(child, &ready);
        git::receive_pack::recover_incomplete_pushes(&database)
            .expect("recover the interrupted push");

        let store = store::Store::open(&database).expect("open the recovered intent store");
        assert!(
            store
                .incomplete_git_intents()
                .expect("list incomplete intents")
                .is_empty(),
            "{boundary} left an incomplete intent"
        );
        let events = store
            .connection()
            .query_row("SELECT count(*) FROM git_operation_event", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("count Git events");
        if matches!(boundary, "refs" | "completed") {
            assert_eq!(rev_parse(&bare, "refs/heads/main"), proposed);
            assert_eq!(events, 1);
        } else {
            assert_missing_ref(&bare, "refs/heads/main");
            assert_missing_object(&bare, &proposed);
            assert_eq!(events, 0);
        }
        let quarantine = bare.join("objects/tit-quarantine");
        let entries = fs::read_dir(&quarantine)
            .map(|entries| entries.count())
            .unwrap_or(0);
        assert_eq!(entries, 0, "{boundary} left a quarantine directory");
    }
}

#[test]
fn fuzzed_packet_lines_and_pack_inputs_do_not_panic() {
    let directory = TempDir::new().expect("create a fuzz fixture directory");
    let repositories_root = directory.path().join("repositories");
    let bare = repositories_root.join("alice/example.git");
    fs::create_dir_all(bare.parent().expect("a bare repository parent"))
        .expect("create a repository owner directory");
    run(Command::new("git")
        .args(["init", "-q", "--bare", "--object-format", "sha1"])
        .arg(&bare));
    let database = directory.path().join("tit.db");
    store::Store::open(&database).expect("create the intent store");
    let mut command = Vec::new();
    git::packetline::encode_data(
        b"0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/main\0 report-status\n",
        &mut command,
    )
    .expect("encode a receive-pack command");
    git::packetline::encode_flush(&mut command);

    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for length in 0..256 {
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push(state as u8);
        }
        std::panic::catch_unwind(|| {
            let _ = git::packetline::decode(&bytes);
            let _ = git::packetline::first_flush_end(&bytes);
        })
        .expect("packet-line parsing must not panic");

        let mut receive =
            git::receive_pack::ReceivePack::open(&bare, &database, "SHA256:fuzz-key".to_owned())
                .expect("open receive-pack for fuzz input");
        fs::write(receive.incoming_pack(), &bytes).expect("write a fuzz pack");
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = receive.finish(&command);
        }))
        .expect("pack parsing must not panic");
    }
    git::receive_pack::recover_incomplete_pushes(&database)
        .expect("recover rejected fuzz operations");
}

fn spawn_push_crash_child(
    boundary: &str,
    repositories: &Path,
    database: &Path,
    worktree: &Path,
    private_key: &Path,
    ready: &Path,
) -> Child {
    Command::new(env::current_exe().expect("find the integration test executable"))
        .args([
            "--exact",
            "git_push_crash_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("TIT_M1D_CHILD_MODE", boundary)
        .env("TIT_M1D_CRASH_AFTER", boundary)
        .env("TIT_M1D_REPOSITORIES", repositories)
        .env("TIT_M1D_DATABASE", database)
        .env("TIT_M1D_WORKTREE", worktree)
        .env("TIT_M1D_PRIVATE_KEY", private_key)
        .env("TIT_M1D_READY", ready)
        .spawn()
        .expect("start the push crash-test child")
}

fn kill_after_ready(mut child: Child, ready: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
        if let Some(status) = child.try_wait().expect("inspect the push crash-test child") {
            panic!("push crash-test child stopped before it was ready: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "push crash-test child was not ready"
        );
        thread::sleep(Duration::from_millis(10));
    }
    child.kill().expect("kill the push crash-test child");
    child.wait().expect("wait for the push crash-test child");
}

fn required_path(name: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("read {name}"))
}

fn create_worktree(path: &Path, format: &str) {
    run(Command::new("git")
        .args(["init", "-q", "--object-format", format, "-b", "main"])
        .arg(path));
    for (name, value) in [
        ("user.name", "Tit Test"),
        ("user.email", "tit@example.invalid"),
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
    ] {
        run(Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["config", name, value]));
    }
    fs::write(path.join("first.txt"), b"first commit\n").expect("write the first file");
    run(Command::new("git").arg("-C").arg(path).args(["add", "."]));
    run(Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["commit", "-q", "-m", "first commit"]));
}

fn create_key(path: &Path) {
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path));
}

fn parse_key(private_key: &Path) -> SshPublicKey {
    let mut public_key = private_key.as_os_str().to_owned();
    public_key.push(".pub");
    let encoded = fs::read_to_string(PathBuf::from(public_key)).expect("read the public key");
    SshPublicKey::parse(&encoded).expect("parse the public key")
}

fn push(worktree: &Path, private_key: &Path, url: &str, refs: &[&str]) -> Output {
    let output = push_result(worktree, private_key, url, refs);
    assert!(
        output.status.success(),
        "stock Git push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn push_result(worktree: &Path, private_key: &Path, url: &str, refs: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(worktree)
        .arg("push")
        .arg(url)
        .args(refs)
        .env("GIT_SSH_COMMAND", ssh_command(private_key))
        .env("GIT_SSH_VARIANT", "ssh")
        .env("GIT_TRACE_PACKET", "1")
        .output()
        .expect("run stock Git push")
}

fn ssh_command(private_key: &Path) -> String {
    format!(
        "ssh -F /dev/null -i {} -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no",
        private_key.display()
    )
}

fn head(path: &Path) -> String {
    rev_parse(path, "HEAD")
}

fn rev_parse(path: &Path, name: &str) -> String {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(path)
        .args(["rev-parse", name])
        .output()
        .expect("run stock Git rev-parse");
    let output = if output.status.success() {
        output
    } else {
        Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["rev-parse", name])
            .output()
            .expect("run worktree Git rev-parse")
    };
    assert!(
        output.status.success(),
        "rev-parse {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("read an object ID")
        .trim()
        .to_owned()
}

fn assert_missing_ref(repository: &Path, name: &str) {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(repository)
        .args(["show-ref", "--verify", "--quiet", name])
        .output()
        .expect("inspect a missing ref");
    assert!(!output.status.success(), "{name} still exists");
}

fn assert_missing_object(repository: &Path, id: &str) {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(repository)
        .args(["cat-file", "-e", id])
        .output()
        .expect("inspect a rejected object");
    assert!(!output.status.success(), "rejected object {id} is visible");
}

fn run(command: &mut Command) -> Output {
    let output = command.output().expect("run stock command");
    assert!(
        output.status.success(),
        "stock command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
