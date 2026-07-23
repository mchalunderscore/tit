#[allow(
    dead_code,
    reason = "the SSH Git test does not use each authentication API"
)]
#[path = "../src/auth.rs"]
mod auth;
#[allow(
    dead_code,
    reason = "the SSH Git test does not use each Git service API"
)]
#[path = "../src/git/mod.rs"]
mod git;
#[allow(
    dead_code,
    reason = "the SSH Git test does not inspect the request audit"
)]
#[path = "../src/ssh.rs"]
mod ssh;
#[allow(dead_code, reason = "the SSH Git test does not use the intent store")]
#[path = "../src/store/mod.rs"]
mod store;

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;

use auth::SshPublicKey;
use git::transport::GitRepositories;
use ssh::RunningSshServer;
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stock_git_clones_and_fetches_both_hash_formats_over_ssh() {
    for format in ["sha1", "sha256"] {
        let directory = TempDir::new().expect("create an SSH Git fixture directory");
        let repositories_root = directory.path().join("repositories");
        let bare = repositories_root.join("alice/example.git");
        let worktree = directory.path().join("worktree");
        create_fixture(&worktree, &bare, format);

        let private_key = directory.path().join("id_ed25519");
        create_key(&private_key);
        let key = parse_key(&private_key);
        let repositories =
            GitRepositories::new(&repositories_root).expect("open the repository root");
        let server = RunningSshServer::start_with_git(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &[key],
            repositories,
        )
        .await
        .expect("start the SSH Git server");
        let ssh_command = ssh_command(&private_key);

        let versions: &[&str] = if format == "sha1" {
            &["0", "1", "2"]
        } else {
            &["1", "2"]
        };
        for version in versions {
            let clone = directory.path().join(format!("clone-v{version}"));
            let url = format!(
                "ssh://ignored@{}:{}/alice/example",
                server.address().ip(),
                server.address().port()
            );
            let output = Command::new("git")
                .args(["-c", &format!("protocol.version={version}"), "clone", "-q"])
                .arg(&url)
                .arg(&clone)
                .env("GIT_SSH_COMMAND", &ssh_command)
                .env("GIT_SSH_VARIANT", "ssh")
                .env("GIT_TRACE_PACKET", "1")
                .output()
                .expect("run stock Git clone");
            assert!(
                output.status.success(),
                "stock Git v{version} clone failed: {}; audit: {:?}",
                String::from_utf8_lossy(&output.stderr),
                server.audit()
            );
            let cloned_head = head(&clone);
            let source_head = head(&worktree);
            assert_eq!(cloned_head, source_head);
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
                b"SSH Git fixture\n"
            );
            assert_eq!(
                fs::metadata(clone.join("large-copy.bin"))
                    .expect("inspect a cloned large blob")
                    .len(),
                2 * 1024 * 1024
            );

            let filename = format!("ssh-fetch-v{version}.txt");
            fs::write(
                worktree.join(&filename),
                format!("payload for {filename}\n"),
            )
            .expect("write an SSH fetch fixture file");
            run(Command::new("git")
                .arg("-C")
                .arg(&worktree)
                .args(["add", &filename]));
            run(Command::new("git").arg("-C").arg(&worktree).args([
                "commit",
                "-q",
                "-m",
                &format!("add {filename}"),
            ]));
            run(Command::new("git").arg("-C").arg(&worktree).args([
                "push",
                "-q",
                &bare.to_string_lossy(),
                "main",
            ]));
            let output = Command::new("git")
                .arg("-C")
                .arg(&clone)
                .args(["-c", &format!("protocol.version={version}"), "fetch", "-q"])
                .env("GIT_SSH_COMMAND", &ssh_command)
                .env("GIT_SSH_VARIANT", "ssh")
                .env("GIT_TRACE_PACKET", "1")
                .output()
                .expect("run stock Git fetch");
            assert!(
                output.status.success(),
                "stock Git v{version} fetch failed: {}; audit: {:?}",
                String::from_utf8_lossy(&output.stderr),
                server.audit()
            );
            assert_eq!(
                rev_parse(&clone, "refs/remotes/origin/main"),
                head(&worktree)
            );
        }

        server.shutdown().await.expect("stop the SSH Git server");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stock_git_clones_empty_repositories_for_both_hash_formats_over_ssh() {
    for format in ["sha1", "sha256"] {
        let directory = TempDir::new().expect("create an empty SSH Git fixture directory");
        let repositories_root = directory.path().join("repositories");
        let bare = repositories_root.join("alice/empty.git");
        fs::create_dir_all(bare.parent().expect("an empty repository parent"))
            .expect("create an empty repository owner directory");
        run(Command::new("git")
            .args(["init", "-q", "--bare", "--object-format", format])
            .arg(&bare));

        let private_key = directory.path().join("id_ed25519");
        create_key(&private_key);
        let repositories =
            GitRepositories::new(&repositories_root).expect("open the repository root");
        let server = RunningSshServer::start_with_git(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &[parse_key(&private_key)],
            repositories,
        )
        .await
        .expect("start the SSH Git server");
        let clone = directory.path().join("clone");
        let output = Command::new("git")
            .args(["-c", "protocol.version=2", "clone", "-q"])
            .arg(format!(
                "ssh://ignored@{}:{}/alice/empty",
                server.address().ip(),
                server.address().port()
            ))
            .arg(&clone)
            .env("GIT_SSH_COMMAND", ssh_command(&private_key))
            .env("GIT_SSH_VARIANT", "ssh")
            .output()
            .expect("clone an empty repository with stock Git");
        assert!(
            output.status.success(),
            "empty SHA-{format} clone failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let head = Command::new("git")
            .arg("-C")
            .arg(&clone)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("inspect the empty clone");
        assert!(!head.status.success());
        server.shutdown().await.expect("stop the SSH Git server");
    }
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
    fs::write(
        worktree.join("non-ascii-\u{00e5}.txt"),
        b"SSH Git fixture\n",
    )
    .expect("write the SSH fixture file");
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
        .arg("-C")
        .arg(path)
        .args(["rev-parse", name])
        .output()
        .expect("run stock Git rev-parse");
    assert!(
        output.status.success(),
        "rev-parse {name} in {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("read an object ID")
        .trim()
        .to_owned()
}

fn run(command: &mut Command) -> std::process::Output {
    let output = command.output().expect("run stock command");
    assert!(
        output.status.success(),
        "stock command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
