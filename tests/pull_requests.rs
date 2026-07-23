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
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use git::read::{Mergeability, ReadCancellation, ReadError, ReadLimits, RepositoryReadService};
use git::repository::GitRepository;
use gix::hash::ObjectId;
use pull_request::{PullRequestError, PullRequestService};
use rusqlite::params;
use store::{GitOperationIntent, NewPullRequestMerge, NewPullRequestRefIntent, Store, StoreError};
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
        let comparison = service
            .compare("alice", "project", 1, None, None)
            .expect("compare the first revision");
        assert_eq!(comparison.detail.pull_request.number, 1);
        assert_eq!(comparison.revision.number, 1);
        assert_eq!(
            comparison.comparison.mergeability,
            Mergeability::FastForward
        );
        assert_eq!(comparison.comparison.commits.len(), 1);
        assert_eq!(comparison.comparison.changed_paths, [b"feature.txt"]);
        assert_eq!(comparison.comparison.files.len(), 1);
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
        let original_comparison = service
            .compare("alice", "project", 1, Some(1), Some("alice"))
            .expect("compare the immutable first revision");
        assert_eq!(
            original_comparison.revision.head_object_id,
            opened.head_object_id
        );
        assert_eq!(original_comparison.comparison.commits.len(), 1);
        let current_comparison = service
            .compare("alice", "project", 1, None, Some("alice"))
            .expect("compare the current revision");
        assert_eq!(current_comparison.revision.number, 2);
        assert_eq!(current_comparison.comparison.commits.len(), 2);

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

#[test]
fn fast_forwards_pull_requests_with_one_durable_merge_event_for_both_hashes() {
    for (index, object_format) in ["sha1", "sha256"].into_iter().enumerate() {
        let fixture = Fixture::new(object_format, index + 30);
        let service = PullRequestService::new(&fixture.database, &fixture.repositories);
        let opened = service
            .open(
                "alice",
                "project",
                "alice",
                "Fast-forward the feature",
                "Move the base ref to the reviewed head.",
                "refs/heads/main",
                "refs/heads/feature",
            )
            .expect("open a fast-forward pull request");
        assert!(matches!(
            service.merge("alice", "project", 1, "bob", "fast-forward"),
            Err(PullRequestError::Store(StoreError::PullRequestDenied))
        ));

        let merged = service
            .merge("alice", "project", 1, "alice", "fast-forward")
            .expect("fast-forward the pull request");
        assert_eq!(merged.state, "merged");
        assert_eq!(
            rev_parse(&fixture.bare, "refs/heads/main"),
            opened.head_object_id
        );
        assert!(matches!(
            service.merge("alice", "project", 1, "alice", "fast-forward"),
            Err(PullRequestError::Store(StoreError::PullRequestState))
        ));

        let store = Store::open(&fixture.database).expect("open the merge store");
        let intent_state: String = store
            .connection()
            .query_row(
                "SELECT git_operation_intent.state
                 FROM pull_request_merge_intent
                 JOIN git_operation_intent
                   ON git_operation_intent.id = pull_request_merge_intent.intent_id",
                [],
                |row| row.get(0),
            )
            .expect("read the merge intent");
        assert_eq!(intent_state, "completed");
        let events: Vec<String> = store
            .connection()
            .prepare(
                "SELECT kind FROM repository_event
                 WHERE sequence > 1 ORDER BY sequence",
            )
            .expect("prepare merge events")
            .query_map([], |row| row.get(0))
            .expect("query merge events")
            .collect::<Result<_, _>>()
            .expect("read merge events");
        assert_eq!(events, ["push", "ref-updated", "pull-request-merged",]);
    }
}

#[test]
fn rejects_a_merge_when_the_base_moved_after_the_revision() {
    let fixture = Fixture::new("sha1", 40);
    let service = PullRequestService::new(&fixture.database, &fixture.repositories);
    service
        .open(
            "alice",
            "project",
            "alice",
            "Stale base",
            "Do not merge a stale comparison.",
            "refs/heads/main",
            "refs/heads/feature",
        )
        .expect("open a pull request");
    fixture.commit_on("main", "base.txt", "new base\n", "move the base");
    assert!(matches!(
        service.merge("alice", "project", 1, "alice", "fast-forward"),
        Err(PullRequestError::StaleRevision)
    ));
    let count: i64 = Store::open(&fixture.database)
        .expect("open the stale merge store")
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM pull_request_merge_intent",
            [],
            |row| row.get(0),
        )
        .expect("count merge intents");
    assert_eq!(count, 0);
}

#[test]
fn creates_worktree_free_merge_commits_with_deterministic_parents_for_both_hashes() {
    for (index, object_format) in ["sha1", "sha256"].into_iter().enumerate() {
        let fixture = Fixture::new(object_format, index + 50);
        fixture.commit_on("main", "base.txt", "base side\n", "advance base");
        run(
            &fixture.worktree,
            Command::new("git").args(["switch", "-q", "feature"]),
        );
        run(
            &fixture.worktree,
            Command::new("git").args(["mv", "feature.txt", "renamed-feature.txt"]),
        );
        let renamed = fixture.worktree.join("renamed-feature.txt");
        fs::set_permissions(&renamed, fs::Permissions::from_mode(0o755))
            .expect("set the executable mode");
        git_commit(&fixture.worktree, "rename the feature");
        run(
            &fixture.worktree,
            Command::new("git")
                .args(["push", "-q"])
                .arg(&fixture.bare)
                .arg("feature"),
        );

        let git = GitRepository::open(&fixture.bare).expect("open the merge repository");
        let base = git
            .resolve_branch("refs/heads/main")
            .expect("resolve the merge base");
        let head = git
            .resolve_branch("refs/heads/feature")
            .expect("resolve the merge head");
        let object_state = git_object_state(&fixture.bare);
        let first = git
            .prepare_merge_commit(base, head, "alice", 1234, "deterministic merge")
            .expect("prepare a merge commit");
        let second = git
            .prepare_merge_commit(base, head, "alice", 1234, "deterministic merge")
            .expect("prepare the same merge commit");
        assert_eq!(first, second);
        assert_eq!(git_object_state(&fixture.bare), object_state);
        assert!(!fixture.bare.join("index").exists());

        let service = PullRequestService::new(&fixture.database, &fixture.repositories);
        service
            .open(
                "alice",
                "project",
                "alice",
                "Merge the rename",
                "Keep the rename and executable mode.",
                "refs/heads/main",
                "refs/heads/feature",
            )
            .expect("open a divergent pull request");
        service
            .merge("alice", "project", 1, "alice", "merge-commit")
            .expect("create a merge commit");
        let merged = rev_parse(&fixture.bare, "refs/heads/main");
        assert_ne!(merged, base.to_string());
        assert_ne!(merged, head.to_string());
        let description = git_output(
            &fixture.bare,
            &["show", "-s", "--format=%an|%ae|%cn|%ce|%P|%s", &merged],
        );
        let expected = format!(
            "alice|alice@users.tit|alice|alice@users.tit|{base} {head}|Merge pull request #1 from refs/heads/feature"
        );
        assert_eq!(description.trim(), expected);
        let tree = git_output(&fixture.bare, &["ls-tree", "-r", &merged]);
        assert!(tree.contains("100755 blob"));
        assert!(tree.contains("\trenamed-feature.txt"));
        assert!(tree.contains("\tbase.txt"));
        assert!(!fixture.bare.join("index").exists());
    }
}

#[test]
fn rejects_a_conflicting_server_merge_without_moving_the_base() {
    let fixture = Fixture::new("sha1", 60);
    fixture.commit_on("main", "README.md", "main content\n", "change main");
    fixture.commit_on(
        "feature",
        "README.md",
        "feature content\n",
        "change feature",
    );
    let base = rev_parse(&fixture.bare, "refs/heads/main");
    let service = PullRequestService::new(&fixture.database, &fixture.repositories);
    service
        .open(
            "alice",
            "project",
            "alice",
            "Conflicting merge",
            "Do not create a conflict commit.",
            "refs/heads/main",
            "refs/heads/feature",
        )
        .expect("open a conflicting pull request");
    assert!(matches!(
        service.merge("alice", "project", 1, "alice", "merge-commit"),
        Err(PullRequestError::Mergeability)
    ));
    assert_eq!(rev_parse(&fixture.bare, "refs/heads/main"), base);
    let count: i64 = Store::open(&fixture.database)
        .expect("open the conflict store")
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM pull_request_merge_intent",
            [],
            |row| row.get(0),
        )
        .expect("count conflict intents");
    assert_eq!(count, 0);
}

#[test]
fn recovers_a_completed_merge_and_abandons_a_concurrent_base_change() {
    let fixture = Fixture::new("sha1", 70);
    let service = PullRequestService::new(&fixture.database, &fixture.repositories);
    service
        .open(
            "alice",
            "project",
            "alice",
            "Recover this merge",
            "Complete metadata after the ref update.",
            "refs/heads/main",
            "refs/heads/feature",
        )
        .expect("open a recoverable pull request");
    begin_test_merge_intent(&fixture, 1, "71000000000000000000000000000000");
    let git = GitRepository::open(&fixture.bare).expect("open the recovery repository");
    let base = git
        .resolve_branch("refs/heads/main")
        .expect("resolve the recovery base");
    let head = git
        .resolve_branch("refs/heads/feature")
        .expect("resolve the recovery head");
    git.update_reference_with_log("refs/heads/main", Some(base), head, "interrupted merge")
        .expect("apply the interrupted merge ref");
    service.recover().expect("recover merge metadata");
    assert_eq!(
        service
            .get("alice", "project", 1, Some("alice"))
            .expect("read the recovered merge")
            .pull_request
            .state,
        "merged"
    );

    let concurrent = Fixture::new("sha1", 71);
    let service = PullRequestService::new(&concurrent.database, &concurrent.repositories);
    service
        .open(
            "alice",
            "project",
            "alice",
            "Race the base",
            "A concurrent base update wins before this ref moves.",
            "refs/heads/main",
            "refs/heads/feature",
        )
        .expect("open a concurrent pull request");
    begin_test_merge_intent(&concurrent, 1, "72000000000000000000000000000000");
    concurrent.commit_on("main", "raced.txt", "concurrent\n", "race the merge");
    let raced_target = rev_parse(&concurrent.bare, "refs/heads/main");
    service
        .recover()
        .expect("abandon the merge that did not update its ref");
    assert_eq!(rev_parse(&concurrent.bare, "refs/heads/main"), raced_target);
    assert_eq!(
        service
            .get("alice", "project", 1, Some("alice"))
            .expect("read the unmerged pull request")
            .pull_request
            .state,
        "open"
    );
    let store = Store::open(&concurrent.database).expect("open the raced merge store");
    let state: String = store
        .connection()
        .query_row(
            "SELECT state FROM git_operation_intent WHERE id = ?1",
            ["72000000000000000000000000000000"],
            |row| row.get(0),
        )
        .expect("read the raced intent state");
    assert_eq!(state, "abandoned");
    let merge_count: i64 = store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM pull_request_merge_intent",
            [],
            |row| row.get(0),
        )
        .expect("count active merge metadata");
    assert_eq!(merge_count, 0);
}

#[test]
fn classifies_clean_conflicting_and_already_merged_revisions_for_both_hashes() {
    for (index, object_format) in ["sha1", "sha256"].into_iter().enumerate() {
        let fixture = Fixture::new(object_format, index + 10);
        fixture.commit_on("main", "base.txt", "base side\n", "advance base");
        fixture.commit_on(
            "feature",
            "feature-two.txt",
            "feature side\n",
            "advance feature",
        );
        let service = PullRequestService::new(&fixture.database, &fixture.repositories);
        service
            .open(
                "alice",
                "project",
                "alice",
                "Clean divergence",
                "The branches change different paths.",
                "refs/heads/main",
                "refs/heads/feature",
            )
            .expect("open a clean divergent pull request");
        let object_state = git_object_state(&fixture.bare);
        let clean = service
            .compare("alice", "project", 1, None, None)
            .expect("compare clean divergence");
        assert_eq!(clean.comparison.mergeability, Mergeability::Clean);
        assert_eq!(clean.comparison.changed_paths.len(), 2);
        assert_eq!(git_object_state(&fixture.bare), object_state);

        fixture.commit_on("main", "README.md", "main content\n", "change base content");
        fixture.commit_on(
            "feature",
            "README.md",
            "feature content\n",
            "change feature content",
        );
        service
            .open(
                "alice",
                "project",
                "alice",
                "Conflicting divergence",
                "The branches change the same line.",
                "refs/heads/main",
                "refs/heads/feature",
            )
            .expect("open a conflicting pull request");
        let object_state = git_object_state(&fixture.bare);
        let conflicting = service
            .compare("alice", "project", 2, None, None)
            .expect("compare conflicting divergence");
        assert_eq!(
            conflicting.comparison.mergeability,
            Mergeability::Conflicting
        );
        assert_eq!(git_object_state(&fixture.bare), object_state);

        fixture.merge_feature_into_main();
        service
            .open(
                "alice",
                "project",
                "alice",
                "Merged head",
                "The head is already in the base.",
                "refs/heads/main",
                "refs/heads/feature",
            )
            .expect("open an already merged pull request");
        let merged = service
            .compare("alice", "project", 3, None, None)
            .expect("compare an already merged head");
        assert_eq!(merged.comparison.mergeability, Mergeability::AlreadyMerged);

        fixture.create_unrelated_branch();
        service
            .open(
                "alice",
                "project",
                "alice",
                "Unrelated head",
                "The branches do not have a common commit.",
                "refs/heads/main",
                "refs/heads/unrelated",
            )
            .expect("open an unrelated pull request");
        let unrelated = service
            .compare("alice", "project", 4, None, None)
            .expect("compare unrelated histories");
        assert_eq!(unrelated.comparison.mergeability, Mergeability::Unrelated);
        assert_eq!(unrelated.comparison.merge_base, None);
        assert_eq!(unrelated.comparison.changed_paths, [b"unrelated.txt"]);

        let base = ObjectId::from_hex(merged.revision.base_object_id.as_bytes())
            .expect("parse the base ID");
        let head = ObjectId::from_hex(merged.revision.head_object_id.as_bytes())
            .expect("parse the head ID");
        let limits = ReadLimits {
            max_history_commits: 1,
            ..ReadLimits::default()
        };
        let reader = RepositoryReadService::open(&fixture.bare, limits)
            .expect("open a limited repository reader");
        assert!(matches!(
            reader.comparison(base, head, &ReadCancellation::default()),
            Err(ReadError::Limit("history commits" | "comparison commits"))
        ));

        let base = ObjectId::from_hex(clean.revision.base_object_id.as_bytes())
            .expect("parse the clean base ID");
        let head = ObjectId::from_hex(clean.revision.head_object_id.as_bytes())
            .expect("parse the clean head ID");
        let limits = ReadLimits {
            max_diff_bytes: 1,
            ..ReadLimits::default()
        };
        let reader = RepositoryReadService::open(&fixture.bare, limits)
            .expect("open an output-limited repository reader");
        assert!(matches!(
            reader.comparison(base, head, &ReadCancellation::default()),
            Err(ReadError::Limit("comparison output bytes" | "diff bytes"))
        ));

        let limits = ReadLimits {
            max_duration: Duration::from_nanos(1),
            ..ReadLimits::default()
        };
        let reader = RepositoryReadService::open(&fixture.bare, limits)
            .expect("open a time-limited repository reader");
        assert!(matches!(
            reader.comparison(base, head, &ReadCancellation::default()),
            Err(ReadError::Deadline)
        ));
    }
}

#[test]
fn records_review_actions_and_immutable_line_anchors_for_both_hashes() {
    for (index, object_format) in ["sha1", "sha256"].into_iter().enumerate() {
        let fixture = Fixture::new(object_format, index + 20);
        let byte_path = "review-å.txt".as_bytes();
        fixture.commit_bytes_on("feature", byte_path, b"byte path\n", "add a byte path");
        let service = PullRequestService::new(&fixture.database, &fixture.repositories);
        service
            .open(
                "alice",
                "project",
                "alice",
                "Review anchors",
                "Keep each review action.",
                "refs/heads/main",
                "refs/heads/feature",
            )
            .expect("open a reviewed pull request");
        service
            .review(
                "alice",
                "project",
                1,
                1,
                "bob",
                "comment",
                "A **general** comment.",
                None,
                None,
                None,
            )
            .expect("add a reader comment");
        service
            .review(
                "alice", "project", 1, 1, "bob", "approved", "", None, None, None,
            )
            .expect("approve the revision");
        service
            .review(
                "alice",
                "project",
                1,
                1,
                "alice",
                "changes-requested",
                "Change this line.",
                None,
                None,
                None,
            )
            .expect("request changes");
        let line_id = service
            .review(
                "alice",
                "project",
                1,
                1,
                "bob",
                "line-comment",
                "Use a clearer value.",
                Some(byte_path),
                Some("head"),
                Some(1),
            )
            .expect("add a line comment");
        assert!(matches!(
            service.review(
                "alice",
                "project",
                1,
                1,
                "bob",
                "line-comment",
                "This line does not exist.",
                Some(byte_path),
                Some("head"),
                Some(2),
            ),
            Err(PullRequestError::ReviewAnchor)
        ));

        fixture.commit_feature("make the line comment outdated");
        service
            .revise("alice", "project", 1, "alice")
            .expect("record a new revision");
        let detail = service
            .get("alice", "project", 1, Some("bob"))
            .expect("read review activity");
        assert_eq!(detail.revisions.len(), 2);
        assert_eq!(detail.reviews.len(), 4);
        let line = detail
            .reviews
            .iter()
            .find(|review| review.id == line_id)
            .expect("find the line review");
        assert_eq!(line.revision, 1);
        assert_eq!(line.path.as_deref(), Some(byte_path));
        assert_eq!(line.side.as_deref(), Some("head"));
        assert_eq!(line.line, Some(1));
        assert_eq!(
            line.commit_object_id.as_deref(),
            Some(detail.revisions[0].head_object_id.as_str())
        );
        assert_eq!(
            detail
                .timeline
                .iter()
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            [
                "pull-request-created",
                "pull-request-commented",
                "pull-request-approved",
                "pull-request-changes-requested",
                "pull-request-line-commented",
                "pull-request-revised",
            ]
        );

        let store = Store::open(&fixture.database).expect("open the review policy store");
        store
            .connection()
            .execute(
                "UPDATE repository SET visibility = 'private' WHERE slug = 'project'",
                [],
            )
            .expect("make the reviewed repository private");
        store
            .connection()
            .execute(
                "DELETE FROM repository_collaborator WHERE account_id = 2",
                [],
            )
            .expect("remove the reader");
        assert!(matches!(
            service.review(
                "alice",
                "project",
                1,
                2,
                "bob",
                "comment",
                "This must stay hidden.",
                None,
                None,
                None,
            ),
            Err(PullRequestError::Store(StoreError::PullRequestHidden))
        ));
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
        run(
            &worktree,
            Command::new("git").args(["config", "user.name", "Tit Test"]),
        );
        run(
            &worktree,
            Command::new("git").args(["config", "user.email", "tit@example.test"]),
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

    fn commit_on(&self, branch: &str, path: &str, content: &str, message: &str) {
        run(
            &self.worktree,
            Command::new("git").args(["switch", "-q", branch]),
        );
        fs::write(self.worktree.join(path), content).expect("write branch content");
        git_commit(&self.worktree, message);
        run(
            &self.worktree,
            Command::new("git")
                .args(["push", "-q"])
                .arg(&self.bare)
                .arg(branch),
        );
    }

    fn commit_bytes_on(&self, branch: &str, path: &[u8], content: &[u8], message: &str) {
        run(
            &self.worktree,
            Command::new("git").args(["switch", "-q", branch]),
        );
        fs::write(
            self.worktree
                .join(std::ffi::OsString::from_vec(path.to_vec())),
            content,
        )
        .expect("write byte-path content");
        git_commit(&self.worktree, message);
        run(
            &self.worktree,
            Command::new("git")
                .args(["push", "-q"])
                .arg(&self.bare)
                .arg(branch),
        );
    }

    fn merge_feature_into_main(&self) {
        run(
            &self.worktree,
            Command::new("git").args(["switch", "-q", "main"]),
        );
        run(
            &self.worktree,
            Command::new("git").args(["merge", "-q", "--no-commit", "-X", "ours", "feature"]),
        );
        git_commit(&self.worktree, "merge feature");
        run(
            &self.worktree,
            Command::new("git")
                .args(["push", "-q"])
                .arg(&self.bare)
                .arg("main"),
        );
    }

    fn create_unrelated_branch(&self) {
        run(
            &self.worktree,
            Command::new("git").args(["switch", "-q", "--orphan", "unrelated"]),
        );
        fs::write(self.worktree.join("unrelated.txt"), b"unrelated\n")
            .expect("write unrelated content");
        git_commit(&self.worktree, "unrelated root");
        run(
            &self.worktree,
            Command::new("git")
                .args(["push", "-q"])
                .arg(&self.bare)
                .arg("unrelated"),
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

fn begin_test_merge_intent(fixture: &Fixture, number: i64, intent_id: &str) {
    let service = PullRequestService::new(&fixture.database, &fixture.repositories);
    let detail = service
        .get("alice", "project", number, Some("alice"))
        .expect("read a merge intent pull request");
    let revision = detail.revisions.last().expect("find the merge revision");
    let git = GitRepository::open(&fixture.bare).expect("open the merge intent repository");
    let base = git
        .resolve_branch("refs/heads/main")
        .expect("resolve the merge intent base");
    let head = git
        .resolve_branch("refs/heads/feature")
        .expect("resolve the merge intent head");
    let initial = format!("{base} refs/heads/main\n").into_bytes();
    let proposed = format!("{head} refs/heads/main\n").into_bytes();
    let created_at = revision.created_at + 1;
    let quarantine = fixture
        .bare
        .join("objects")
        .join("tit-quarantine")
        .join(intent_id);
    let mut store = Store::open(&fixture.database).expect("open the merge intent store");
    store
        .begin_pull_request_merge(
            &NewPullRequestMerge {
                owner: "alice",
                repository: "project",
                number,
                revision: revision.number,
                actor: "alice",
                method: "fast-forward",
                base_ref: "refs/heads/main",
                old_target: &base.to_string(),
                head_target: &head.to_string(),
                new_target: &head.to_string(),
                created_at,
            },
            &GitOperationIntent {
                id: intent_id,
                repository_path: fixture.bare.to_str().expect("a UTF-8 repository path"),
                actor: "alice",
                initial_refs: &initial,
                proposed_refs: &proposed,
                event_payload: &proposed,
                quarantine_path: quarantine.to_str().expect("a UTF-8 quarantine path"),
                created_at,
            },
        )
        .expect("begin a test merge intent");
    store
        .mark_git_objects_promoted(intent_id, None)
        .expect("mark test merge objects promoted");
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

fn git_output(repository: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .output()
        .expect("run a Git inspection command");
    assert!(
        output.status.success(),
        "Git inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("read Git inspection output")
}

fn git_object_state(repository: &Path) -> String {
    let output = Command::new("git")
        .args(["count-objects", "-v"])
        .current_dir(repository)
        .output()
        .expect("count fixture objects");
    assert!(output.status.success(), "count fixture objects");
    String::from_utf8(output.stdout).expect("read the object count")
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
