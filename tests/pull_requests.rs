#[allow(
    dead_code,
    reason = "the pull-request test uses only identity validation"
)]
#[path = "../src/auth.rs"]
mod auth;
#[path = "../src/domain/mod.rs"]
mod domain;
#[allow(
    dead_code,
    reason = "the pull-request test uses part of the shared Git API"
)]
#[path = "../src/git/mod.rs"]
mod git;
#[allow(
    dead_code,
    reason = "the pull-request test uses repository policy through Git"
)]
#[path = "../src/policy.rs"]
mod policy;
#[path = "../src/pull_request.rs"]
mod pull_request;
#[allow(dead_code, reason = "the pull-request test uses part of the store API")]
#[path = "../src/store/mod.rs"]
mod store;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use git::repository::GitRepository;
use pull_request::{PullRequestError, PullRequestService};
use rusqlite::params;
use store::{NewPullRequestRefIntent, Store, StoreError};
use tempfile::TempDir;

#[test]
fn creates_revises_and_recovers_numbered_pull_request_refs_for_both_hashes() {
    for (index, object_format) in ["sha1", "sha256"].into_iter().enumerate() {
        let fixture = Fixture::new(object_format, index);
        let service = PullRequestService::new(&fixture.database, &fixture.repositories);
        let opened = service
            .open(
                "alice",
                "project",
                "alice",
                "Add the feature",
                "Keep the revision context.",
                "refs/heads/main",
                "refs/heads/feature",
            )
            .expect("open a pull request");
        assert_eq!(opened.number, 1);
        assert_eq!(fixture.pull_ref(1), opened.head_object_id);
        run(
            &fixture.worktree,
            Command::new("git")
                .args(["fetch", "-q"])
                .arg(&fixture.bare)
                .arg("refs/pull/1/head"),
        );
        assert_eq!(
            rev_parse(&fixture.worktree, "FETCH_HEAD"),
            opened.head_object_id
        );
        assert!(matches!(
            service.open(
                "alice",
                "project",
                "bob",
                "Reader change",
                "Readers cannot open pull requests.",
                "refs/heads/main",
                "refs/heads/feature",
            ),
            Err(PullRequestError::Store(StoreError::PullRequestDenied))
        ));

        let first = service
            .get("alice", "project", 1, None)
            .expect("read a public pull request");
        assert_eq!(first.revisions.len(), 1);
        assert_eq!(first.revisions[0].head_object_id, opened.head_object_id);

        fixture.commit_feature("second feature revision");
        let revised = service
            .revise("alice", "project", 1, "alice")
            .expect("revise a pull request");
        assert_ne!(revised.head_object_id, opened.head_object_id);
        assert_eq!(fixture.pull_ref(1), revised.head_object_id);
        let second = service
            .get("alice", "project", 1, Some("alice"))
            .expect("read revised pull request");
        assert_eq!(second.revisions.len(), 2);
        assert_eq!(second.revisions[0].head_object_id, opened.head_object_id);
        assert_eq!(second.revisions[1].head_object_id, revised.head_object_id);

        let git = GitRepository::open(&fixture.bare).expect("open the bare fixture");
        let base = git
            .resolve_branch("refs/heads/main")
            .expect("resolve the base");
        let head = git
            .resolve_branch("refs/heads/feature")
            .expect("resolve the head");
        let mut store = Store::open(&fixture.database).expect("open the store");
        let pending = store
            .begin_pull_request_open(&NewPullRequestRefIntent {
                id: "10000000000000000000000000000000",
                pull_request_id: "20000000000000000000000000000000",
                owner: "alice",
                repository: "project",
                actor: "alice",
                title: "Recover the ref",
                body: "The intent exists before the ref.",
                base_ref: "refs/heads/main",
                head_ref: "refs/heads/feature",
                base_object_id: &base.to_string(),
                head_object_id: &head.to_string(),
                created_at: 100,
            })
            .expect("begin a pending pull request");
        assert_eq!(pending.pull_request_number, 2);
        drop(store);
        service.recover().expect("recover a pre-ref intent");
        assert_eq!(fixture.pull_ref(2), head.to_string());
        let recovered = service
            .get("alice", "project", 2, None)
            .expect("read the recovered pull request");
        assert_eq!(recovered.revisions.len(), 1);

        fixture.commit_feature("recovery after ref update");
        let git = GitRepository::open(&fixture.bare).expect("reopen the bare fixture");
        let next_base = git
            .resolve_branch("refs/heads/main")
            .expect("resolve the next base");
        let next_head = git
            .resolve_branch("refs/heads/feature")
            .expect("resolve the next head");
        let mut store = Store::open(&fixture.database).expect("reopen the store");
        let pending_revision = store
            .begin_pull_request_revision(
                2,
                &NewPullRequestRefIntent {
                    id: "30000000000000000000000000000000",
                    pull_request_id: "20000000000000000000000000000000",
                    owner: "alice",
                    repository: "project",
                    actor: "alice",
                    title: "Recover the ref",
                    body: "The intent exists before the ref.",
                    base_ref: "refs/heads/main",
                    head_ref: "refs/heads/feature",
                    base_object_id: &next_base.to_string(),
                    head_object_id: &next_head.to_string(),
                    created_at: 101,
                },
            )
            .expect("begin a pending revision");
        git.update_reference("refs/pull/2/head", Some(head), next_head)
            .expect("apply the ref before metadata");
        drop(store);
        service.recover().expect("recover a post-ref intent");
        let recovered_revision = service
            .get("alice", "project", 2, None)
            .expect("read the recovered revision");
        assert_eq!(recovered_revision.revisions.len(), 2);
        assert_eq!(
            recovered_revision.revisions[1].number,
            pending_revision.revision_number
        );

        let service = Arc::new(service);
        let handles = ["Concurrent A", "Concurrent B"].map(|title| {
            let service = Arc::clone(&service);
            std::thread::spawn(move || {
                service
                    .open(
                        "alice",
                        "project",
                        "alice",
                        title,
                        "Use one stable number.",
                        "refs/heads/main",
                        "refs/heads/feature",
                    )
                    .expect("open a concurrent pull request")
                    .number
            })
        });
        let mut numbers = handles.map(|handle| handle.join().expect("join an opener"));
        numbers.sort_unstable();
        assert_eq!(numbers, [3, 4]);
        assert_eq!(fixture.pull_ref(3), next_head.to_string());
        assert_eq!(fixture.pull_ref(4), next_head.to_string());

        let event_kinds: Vec<String> = Store::open(&fixture.database)
            .expect("open the event store")
            .connection()
            .prepare(
                "SELECT kind FROM repository_event
                 WHERE kind LIKE 'pull-request-%' ORDER BY sequence",
            )
            .expect("prepare the event query")
            .query_map([], |row| row.get(0))
            .expect("query pull-request events")
            .collect::<Result<_, _>>()
            .expect("read pull-request events");
        assert_eq!(
            event_kinds,
            [
                "pull-request-created",
                "pull-request-revised",
                "pull-request-created",
                "pull-request-revised",
                "pull-request-created",
                "pull-request-created"
            ]
        );
    }
}

struct Fixture {
    _directory: TempDir,
    database: PathBuf,
    repositories: PathBuf,
    worktree: PathBuf,
    bare: PathBuf,
}

impl Fixture {
    fn new(object_format: &str, index: usize) -> Self {
        let directory = TempDir::new().expect("create a fixture directory");
        let repositories = directory.path().join("repositories");
        fs::create_dir(&repositories).expect("create a repository directory");
        let repositories = fs::canonicalize(repositories).expect("canonicalize repositories");
        let database = directory.path().join("tit.sqlite3");
        let store = Store::open(&database).expect("create the database");
        store
            .connection()
            .execute(
                "INSERT INTO account
                 (id, username, is_administrator, state, created_at)
                 VALUES (1, 'alice', 1, 'active', 1)",
                [],
            )
            .expect("create the owner");
        store
            .connection()
            .execute(
                "INSERT INTO account
                 (id, username, is_administrator, state, created_at)
                 VALUES (2, 'bob', 0, 'active', 1)",
                [],
            )
            .expect("create a reader");
        let repository_id = format!("{index:032x}");
        store
            .connection()
            .execute(
                "INSERT INTO repository
                 (id, owner_account_id, slug, visibility, state, object_format, created_at)
                 VALUES (?1, 1, 'project', 'public', 'active', ?2, 2)",
                params![repository_id, object_format],
            )
            .expect("create repository metadata");
        store
            .connection()
            .execute(
                "INSERT INTO repository_collaborator
                 (repository_id, account_id, role, created_at)
                 VALUES (?1, 2, 'reader', 2)",
                [&repository_id],
            )
            .expect("grant reader access");
        drop(store);

        let worktree = directory.path().join("worktree");
        run(
            directory.path(),
            Command::new("git")
                .args(["init", "-q", "-b", "main", "--object-format", object_format])
                .arg(&worktree),
        );
        fs::write(worktree.join("README.md"), b"base\n").expect("write base content");
        git_commit(&worktree, "base");
        run(
            &worktree,
            Command::new("git").args(["switch", "-q", "-c", "feature"]),
        );
        fs::write(worktree.join("feature.txt"), b"feature\n").expect("write feature content");
        git_commit(&worktree, "feature");
        let bare = repositories.join(format!("{repository_id}.git"));
        run(
            directory.path(),
            Command::new("git")
                .args(["clone", "-q", "--bare"])
                .arg(&worktree)
                .arg(&bare),
        );
        Self {
            _directory: directory,
            database,
            repositories,
            worktree,
            bare,
        }
    }

    fn commit_feature(&self, message: &str) {
        fs::write(self.worktree.join("feature.txt"), format!("{message}\n"))
            .expect("write revised feature content");
        git_commit(&self.worktree, message);
        run(
            &self.worktree,
            Command::new("git")
                .args(["push", "-q"])
                .arg(&self.bare)
                .arg("feature"),
        );
    }

    fn pull_ref(&self, number: i64) -> String {
        GitRepository::open(&self.bare)
            .expect("open the bare fixture")
            .reference_target(&format!("refs/pull/{number}/head"))
            .expect("read a pull-request ref")
            .expect("find a pull-request ref")
            .to_string()
    }
}

fn git_commit(worktree: &Path, message: &str) {
    run(worktree, Command::new("git").args(["add", "."]));
    let mut command = Command::new("git");
    command
        .args(["commit", "-q", "-m", message])
        .env("GIT_AUTHOR_NAME", "Tit Test")
        .env("GIT_AUTHOR_EMAIL", "tit@example.test")
        .env("GIT_COMMITTER_NAME", "Tit Test")
        .env("GIT_COMMITTER_EMAIL", "tit@example.test")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "commit.gpgsign")
        .env("GIT_CONFIG_VALUE_0", "false");
    run(worktree, &mut command);
}

fn rev_parse(repository: &Path, revision: &str) -> String {
    let output = Command::new("git")
        .args(["rev-parse", revision])
        .current_dir(repository)
        .output()
        .expect("resolve a fixture revision");
    assert!(output.status.success(), "resolve a fixture revision");
    String::from_utf8(output.stdout)
        .expect("read a fixture object ID")
        .trim()
        .to_owned()
}

fn run(directory: &Path, command: &mut Command) {
    let output = command
        .current_dir(directory)
        .output()
        .expect("run a fixture command");
    assert!(
        output.status.success(),
        "fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
