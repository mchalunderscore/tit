#[path = "../src/store/mod.rs"]
mod store;

use std::process::{Child, Command};
use std::sync::mpsc;
use std::sync::{Arc, atomic::AtomicBool, atomic::Ordering};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, ffi::OsString, fs};

use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};
use store::{
    GitOperationIntent, InitialAdministrator, IssueChange, NewAuditEvent, NewIssue, NewRepository,
    NewRepositoryReference, RepositoryOrigin, Store, StoreError,
};
use tempfile::TempDir;

const V1_FIXTURE: &str = include_str!("fixtures/sqlite/v1.sql");
const V2_FIXTURE: &str = include_str!("fixtures/sqlite/v2.sql");
const V3_FIXTURE: &str = include_str!("fixtures/sqlite/v3.sql");
const V4_FIXTURE: &str = include_str!("fixtures/sqlite/v4.sql");
const V5_FIXTURE: &str = include_str!("fixtures/sqlite/v5.sql");
const V6_FIXTURE: &str = include_str!("fixtures/sqlite/v6.sql");
const V7_FIXTURE: &str = include_str!("fixtures/sqlite/v7.sql");
const V8_FIXTURE: &str = concat!(
    include_str!("fixtures/sqlite/v7.sql"),
    include_str!("../src/store/migrations/008_web_sessions.sql"),
    "PRAGMA user_version = 8;\n",
);
const V9_FIXTURE: &str = concat!(
    include_str!("fixtures/sqlite/v7.sql"),
    include_str!("../src/store/migrations/008_web_sessions.sql"),
    include_str!("../src/store/migrations/009_repository_authorization.sql"),
    "PRAGMA user_version = 9;\n",
);
const V10_FIXTURE: &str = concat!(
    include_str!("fixtures/sqlite/v7.sql"),
    include_str!("../src/store/migrations/008_web_sessions.sql"),
    include_str!("../src/store/migrations/009_repository_authorization.sql"),
    include_str!("../src/store/migrations/010_audit_history.sql"),
    "PRAGMA user_version = 10;\n",
);
const V11_FIXTURE: &str = concat!(
    include_str!("fixtures/sqlite/v7.sql"),
    include_str!("../src/store/migrations/008_web_sessions.sql"),
    include_str!("../src/store/migrations/009_repository_authorization.sql"),
    include_str!("../src/store/migrations/010_audit_history.sql"),
    include_str!("../src/store/migrations/011_domain_events.sql"),
    "PRAGMA user_version = 11;\n",
);

fn database(directory: &TempDir, name: &str) -> std::path::PathBuf {
    directory.path().join(name)
}

fn migration_backup(path: &std::path::Path, version: i64) -> std::path::PathBuf {
    let mut backup = OsString::from(path.as_os_str());
    backup.push(format!(".v{version}.backup"));
    backup.into()
}

fn create_fixture(path: &std::path::Path, fixture: &str) {
    let connection = Connection::open(path).expect("open a fixture database");
    connection
        .execute_batch(fixture)
        .expect("create the fixture");
}

fn spawn_crash_child(
    mode: &str,
    database_path: &std::path::Path,
    ready_path: &std::path::Path,
) -> Child {
    Command::new(env::current_exe().expect("find the integration test executable"))
        .args(["--exact", "crash_child", "--nocapture", "--test-threads=1"])
        .env("TIT_M1A_CHILD_MODE", mode)
        .env("TIT_M1A_DATABASE", database_path)
        .env("TIT_M1A_READY", ready_path)
        .spawn()
        .expect("start the crash-test child")
}

fn wait_for_child(child: &mut Child, ready_path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ready_path.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("inspect the crash-test child") {
            panic!("crash-test child stopped before it was ready: {status}");
        }
        assert!(Instant::now() < deadline, "crash-test child was not ready");
        thread::sleep(Duration::from_millis(10));
    }
}

fn kill_child(mut child: Child, ready_path: &std::path::Path) {
    wait_for_child(&mut child, ready_path);
    child.kill().expect("kill the crash-test child");
    child.wait().expect("wait for the crash-test child");
}

fn signal_ready_and_wait() {
    let ready_path = env::var_os("TIT_M1A_READY").expect("read the ready-file path");
    fs::write(ready_path, b"ready").expect("write the ready file");
    loop {
        thread::park();
    }
}

#[test]
fn crash_child() {
    let Some(mode) = env::var_os("TIT_M1A_CHILD_MODE") else {
        return;
    };
    let database_path = env::var_os("TIT_M1A_DATABASE").expect("read the database path");
    let database_path = std::path::Path::new(&database_path);

    match mode.to_str().expect("read the crash-test mode") {
        "write-uncommitted" => {
            let mut store = Store::open(database_path).expect("open the child store");
            let transaction = store
                .connection_mut()
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start the child transaction");
            transaction
                .execute(
                    "INSERT INTO m1a_parent (id, name, created_at) VALUES (1, 'uncommitted', 1)",
                    [],
                )
                .expect("insert an uncommitted row");
            signal_ready_and_wait();
        }
        "write-committed" => {
            let store = Store::open(database_path).expect("open the child store");
            store
                .connection()
                .execute(
                    "INSERT INTO m1a_parent (id, name, created_at) VALUES (1, 'committed', 1)",
                    [],
                )
                .expect("insert a committed row");
            signal_ready_and_wait();
        }
        "migration-uncommitted" => {
            let mut store = Store::open_unmigrated(database_path).expect("open the child fixture");
            store
                .migrate_with_hook(|version| {
                    if version == 2 {
                        signal_ready_and_wait();
                    }
                })
                .expect("migrate the child fixture");
        }
        "migration-committed" => {
            Store::open(database_path).expect("migrate the child fixture");
            signal_ready_and_wait();
        }
        unexpected => panic!("unknown crash-test mode: {unexpected}"),
    }
}

#[test]
fn configures_connections_and_creates_the_current_schema() {
    let directory = TempDir::new().expect("create a temporary directory");
    let store = Store::open(&database(&directory, "store.sqlite")).expect("open the store");

    assert_eq!(store.schema_version().expect("read the schema version"), 12);
    assert_eq!(
        store
            .connection()
            .pragma_query_value::<String, _>(None, "journal_mode", |row| row.get(0))
            .expect("read the journal mode"),
        "wal"
    );
    assert_eq!(
        store
            .connection()
            .pragma_query_value::<i64, _>(None, "synchronous", |row| row.get(0))
            .expect("read the synchronization mode"),
        2
    );
    assert_eq!(
        store
            .connection()
            .pragma_query_value::<i64, _>(None, "foreign_keys", |row| row.get(0))
            .expect("read the foreign-key mode"),
        1
    );
    assert_eq!(
        store
            .connection()
            .pragma_query_value::<i64, _>(None, "busy_timeout", |row| row.get(0))
            .expect("read the busy timeout"),
        5_000
    );
    store.integrity_check().expect("check database integrity");
}

#[test]
fn persists_and_completes_git_operation_intents_with_their_events() {
    let directory = TempDir::new().expect("create a temporary directory");
    let mut store = Store::open(&database(&directory, "store.sqlite")).expect("open the store");
    let intent = GitOperationIntent {
        id: "00112233445566778899aabbccddeeff",
        repository_path: "/srv/tit/repositories/alice/example.git",
        actor: "SHA256:test-key",
        initial_refs: b"0000000000000000000000000000000000000000 refs/heads/main\n",
        proposed_refs: b"1111111111111111111111111111111111111111 refs/heads/main\n",
        event_payload: b"push event",
        quarantine_path: "/srv/tit/repositories/alice/example.git/objects/tit-quarantine/test",
        created_at: 1,
    };
    store.begin_git_intent(&intent).expect("begin an intent");
    let pending = store
        .incomplete_git_intents()
        .expect("list pending intents");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, intent.id);
    assert_eq!(pending[0].repository_path, intent.repository_path);
    assert_eq!(pending[0].initial_refs, intent.initial_refs);
    assert_eq!(pending[0].proposed_refs, intent.proposed_refs);
    assert_eq!(pending[0].quarantine_path, intent.quarantine_path);
    assert_eq!(pending[0].state, "pending");
    assert_eq!(pending[0].pack_name, None);

    store
        .mark_git_objects_promoted(intent.id, Some("pack-test.pack"))
        .expect("mark objects as promoted");
    let promoted = store
        .incomplete_git_intents()
        .expect("list promoted intents");
    assert_eq!(promoted[0].state, "promoted");
    assert_eq!(promoted[0].pack_name.as_deref(), Some("pack-test.pack"));
    store
        .complete_git_intent(intent.id)
        .expect("complete the intent");
    assert!(
        store
            .incomplete_git_intents()
            .expect("list incomplete intents")
            .is_empty()
    );
    assert_eq!(
        store
            .connection()
            .query_row("SELECT count(*) FROM git_operation_event", [], |row| row
                .get::<_, i64>(0))
            .expect("count Git operation events"),
        1
    );

    let abandoned = GitOperationIntent {
        id: "ffeeddccbbaa99887766554433221100",
        ..intent
    };
    store
        .begin_git_intent(&abandoned)
        .expect("begin an abandoned intent");
    store
        .abandon_git_intent(abandoned.id)
        .expect("abandon the intent");
    assert!(
        store
            .incomplete_git_intents()
            .expect("list incomplete intents")
            .is_empty()
    );
}

#[test]
fn creates_only_one_initial_administrator_in_one_transaction() {
    let directory = TempDir::new().expect("create a temporary directory");
    let mut store = Store::open(&database(&directory, "store.sqlite")).expect("open the store");
    let recovery_hash = [7_u8; 32];
    let administrator = InitialAdministrator {
        username: "alice",
        canonical_key: "ssh-ed25519 AAAAexample",
        fingerprint: "SHA256:example",
        recovery_hash: &recovery_hash,
        created_at: 10,
    };
    store
        .create_initial_administrator(&administrator)
        .expect("create the initial administrator");
    let record: (String, i64, String, String, Vec<u8>) = store
        .connection()
        .query_row(
            "SELECT account.username, account.is_administrator, account.state,
                    ssh_public_key.fingerprint, recovery_credential.credential_hash
             FROM account
             JOIN ssh_public_key ON ssh_public_key.account_id = account.id
             JOIN recovery_credential ON recovery_credential.account_id = account.id",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("read the initial administrator");
    assert_eq!(record.0, "alice");
    assert_eq!(record.1, 1);
    assert_eq!(record.2, "active");
    assert_eq!(record.3, "SHA256:example");
    assert_eq!(record.4, recovery_hash);
    assert!(matches!(
        store.create_initial_administrator(&administrator),
        Err(StoreError::AlreadyInitialized)
    ));
    assert_eq!(
        store
            .connection()
            .query_row("SELECT count(*) FROM account", [], |row| row
                .get::<_, i64>(0))
            .expect("count accounts"),
        1
    );
}

#[test]
fn creates_renames_archives_and_reads_owned_repositories() {
    let directory = TempDir::new().expect("create a temporary directory");
    let mut store = Store::open(&database(&directory, "store.sqlite")).expect("open the store");
    let recovery_hash = [7_u8; 32];
    store
        .create_initial_administrator(&InitialAdministrator {
            username: "alice",
            canonical_key: "ssh-ed25519 AAAAexample",
            fingerprint: "SHA256:example",
            recovery_hash: &recovery_hash,
            created_at: 10,
        })
        .expect("create an account");
    let initial_references = [
        NewRepositoryReference {
            name: b"refs/heads/main".to_vec(),
            target: "1".repeat(64),
        },
        NewRepositoryReference {
            name: b"refs/tags/v1".to_vec(),
            target: "2".repeat(64),
        },
    ];
    let repository = NewRepository {
        id: "00112233445566778899aabbccddeeff",
        owner: "alice",
        slug: "project",
        object_format: "sha256",
        created_at: 20,
        origin: RepositoryOrigin::Imported,
        initial_references: &initial_references,
        actor: "admin-cli",
        correlation_id: "test-create",
    };
    store
        .create_repository(&repository)
        .expect("create a repository");
    let created = store
        .repository("alice", "project")
        .expect("read a repository");
    assert_eq!(created.id, repository.id);
    assert_eq!(created.owner, "alice");
    assert_eq!(created.slug, "project");
    assert_eq!(created.visibility, "public");
    assert_eq!(created.state, "active");
    assert_eq!(created.object_format, "sha256");
    assert_eq!(created.created_at, 20);
    assert_eq!(created.archived_at, None);
    let (_, imported_events) = store
        .public_repository_events("alice", "project", None, 10)
        .expect("read imported repository events");
    assert_eq!(imported_events.len(), 3);
    assert_eq!(imported_events[0].kind, "tag-created");
    assert_eq!(imported_events[1].kind, "ref-created");
    assert_eq!(imported_events[2].kind, "repository-imported");
    assert_eq!(
        imported_events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![3, 2, 1]
    );
    for event in &imported_events {
        assert_eq!(event.event_id.len(), 32);
        assert!(
            event
                .event_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(event.payload_version, 1);
        let payload: serde_json::Value =
            serde_json::from_str(&event.payload).expect("parse a versioned event payload");
        assert_eq!(payload["version"], 1);
    }
    let imported_payload: serde_json::Value = serde_json::from_str(&imported_events[2].payload)
        .expect("parse the repository import payload");
    assert_eq!(imported_payload["owner"], "alice");
    assert_eq!(imported_payload["repository"], "project");
    assert_eq!(imported_payload["object_format"], "sha256");
    let event_plan: String = store
        .connection()
        .query_row(
            "EXPLAIN QUERY PLAN
             SELECT event_id FROM repository_event
             WHERE repository_id = ?1 AND sequence < ?2
             ORDER BY sequence DESC LIMIT ?3",
            rusqlite::params![repository.id, 100, 20],
            |row| row.get(3),
        )
        .expect("read the repository event query plan");
    assert!(
        event_plan.contains("repository_event_feed"),
        "query plan: {event_plan}"
    );
    let duplicate_sequence = store
        .connection()
        .execute(
            "INSERT INTO repository_event
             (event_id, repository_id, sequence, kind, actor, payload_version,
              payload, created_at)
             VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', ?1, 1, 'push', 'alice',
                     1, '{\"version\":1}', 20)",
            [repository.id],
        )
        .expect_err("reject a duplicate repository event sequence");
    assert_eq!(
        duplicate_sequence.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    );
    let unversioned_payload = store
        .connection()
        .execute(
            "INSERT INTO repository_event
             (event_id, repository_id, sequence, kind, actor, payload_version,
              payload, created_at)
             VALUES ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', ?1, 4, 'push', 'alice',
                     1, '{}', 20)",
            [repository.id],
        )
        .expect_err("reject an unversioned repository event payload");
    assert_eq!(
        unversioned_payload.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    );
    store
        .connection()
        .execute_batch(
            "CREATE TEMP TRIGGER reject_repository_event
             BEFORE INSERT ON repository_event
             BEGIN
                 SELECT RAISE(ABORT, 'injected event failure');
             END;",
        )
        .expect("install an event failure trigger");
    let rejected_repository = NewRepository {
        id: "11111111111111111111111111111111",
        owner: "alice",
        slug: "event-failure",
        object_format: "sha1",
        created_at: 20,
        origin: RepositoryOrigin::Created,
        initial_references: &[],
        actor: "alice",
        correlation_id: "test-event-failure",
    };
    assert!(matches!(
        store.create_repository(&rejected_repository),
        Err(StoreError::Sqlite(_))
    ));
    assert!(matches!(
        store.repository("alice", "event-failure"),
        Err(StoreError::RepositoryNotFound(_, _))
    ));
    store
        .connection()
        .execute_batch("DROP TRIGGER reject_repository_event;")
        .expect("remove the event failure trigger");

    let initial = format!("{} refs/heads/main\n", "0".repeat(64));
    let proposed = format!("{} refs/heads/main\n", "a".repeat(64));
    let push = GitOperationIntent {
        id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        repository_path: "/srv/tit/repositories/00112233445566778899aabbccddeeff.git",
        actor: "alice",
        initial_refs: initial.as_bytes(),
        proposed_refs: proposed.as_bytes(),
        event_payload: proposed.as_bytes(),
        quarantine_path: "/srv/tit/quarantine/push",
        created_at: 21,
    };
    store.begin_git_intent(&push).expect("begin a managed push");
    let (_, pending_events) = store
        .public_repository_events("alice", "project", None, 10)
        .expect("read events while a push is pending");
    assert_eq!(pending_events.len(), 3);
    store
        .mark_git_objects_promoted(push.id, None)
        .expect("promote a managed push");
    let (_, promoted_events) = store
        .public_repository_events("alice", "project", None, 10)
        .expect("read events while a push is promoted");
    assert_eq!(promoted_events.len(), 3);
    store
        .connection()
        .execute_batch(
            "CREATE TEMP TRIGGER reject_push_event
             BEFORE INSERT ON repository_event
             BEGIN
                 SELECT RAISE(ABORT, 'injected push event failure');
             END;",
        )
        .expect("install a push event failure trigger");
    assert!(matches!(
        store.complete_git_intent(push.id),
        Err(StoreError::Sqlite(_))
    ));
    assert!(
        !store
            .git_intent_completed(push.id)
            .expect("read the rolled-back intent state")
    );
    let (_, rolled_back_events) = store
        .public_repository_events("alice", "project", None, 10)
        .expect("read events after the failed completion");
    assert_eq!(rolled_back_events.len(), 3);
    store
        .connection()
        .execute_batch("DROP TRIGGER reject_push_event;")
        .expect("remove the push event failure trigger");
    store
        .complete_git_intent(push.id)
        .expect("complete a managed push");
    assert!(
        store
            .git_intent_completed(push.id)
            .expect("read the completed intent")
    );
    let (_, pushed_events) = store
        .public_repository_events("alice", "project", None, 10)
        .expect("read pushed repository events");
    assert_eq!(pushed_events.len(), 5);
    assert_eq!(
        pushed_events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![5, 4, 3, 2, 1]
    );
    assert_eq!(pushed_events[0].kind, "ref-created");
    assert_eq!(
        pushed_events[0].new_target.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(pushed_events[1].kind, "push");
    let push_payload: serde_json::Value =
        serde_json::from_str(&pushed_events[1].payload).expect("parse the push payload");
    assert_eq!(push_payload["operation_id"], push.id);
    let (_, older_events) = store
        .public_repository_events("alice", "project", Some(4), 10)
        .expect("read events before a repository sequence");
    assert_eq!(
        older_events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![3, 2, 1]
    );
    let event_ids = pushed_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let reopened = Store::open(&database(&directory, "store.sqlite"))
        .expect("reopen the repository event store");
    let (_, reopened_events) = reopened
        .public_repository_events("alice", "project", None, 10)
        .expect("read repository events after a reopen");
    assert_eq!(
        reopened_events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>(),
        event_ids
    );
    drop(reopened);
    let audits = store.audit_events(10).expect("read audit history");
    assert_eq!(audits.len(), 2);
    assert_eq!(audits[0].action, "ref.update");
    assert_eq!(audits[0].actor, "alice");
    assert_eq!(audits[0].target, repository.id);
    assert_eq!(audits[0].outcome, "success");
    assert_eq!(audits[0].correlation_id, push.id);
    assert_eq!(audits[1].action, "repository.import");
    assert_eq!(audits[1].created_at, 20);
    assert!(matches!(store.audit_events(0), Err(StoreError::AuditLimit)));
    store
        .record_audit_event(&NewAuditEvent {
            action: "repository.rename",
            actor: "admin-cli",
            target: "alice/missing",
            outcome: "failure",
            correlation_id: "test-failure",
            created_at: 22,
        })
        .expect("record an audit failure");
    assert_eq!(
        store.audit_events(1).expect("read the newest audit event")[0].outcome,
        "failure"
    );

    assert!(matches!(
        store.create_repository(&repository),
        Err(StoreError::RepositoryIdentifierCollision)
    ));
    let duplicate_name = NewRepository {
        id: "ffeeddccbbaa99887766554433221100",
        ..repository
    };
    assert!(matches!(
        store.create_repository(&duplicate_name),
        Err(StoreError::RepositoryExists(owner, slug))
            if owner == "alice" && slug == "project"
    ));
    let missing_owner = NewRepository {
        id: "1234567890abcdef1234567890abcdef",
        owner: "bob",
        slug: "project",
        object_format: "sha1",
        created_at: 20,
        origin: RepositoryOrigin::Created,
        initial_references: &[],
        actor: "admin-cli",
        correlation_id: "test-missing",
    };
    assert!(matches!(
        store.create_repository(&missing_owner),
        Err(StoreError::AccountNotFound(owner)) if owner == "bob"
    ));
    let (_, unchanged_events) = store
        .public_repository_events("alice", "project", None, 10)
        .expect("read events after rejected repository mutations");
    assert_eq!(unchanged_events.len(), 5);

    store
        .rename_repository(
            "alice",
            "project",
            "renamed",
            25,
            "admin-cli",
            "test-rename",
        )
        .expect("rename a repository");
    assert!(matches!(
        store.repository("alice", "project"),
        Err(StoreError::RepositoryNotFound(_, _))
    ));
    store
        .archive_repository("alice", "renamed", 30, "admin-cli", "test-archive")
        .expect("archive a repository");
    let archived = store
        .repository("alice", "renamed")
        .expect("read the archived repository");
    assert_eq!(archived.state, "archived");
    assert_eq!(archived.archived_at, Some(30));
    assert!(matches!(
        store.archive_repository("alice", "renamed", 31, "admin-cli", "test-archive-fail"),
        Err(StoreError::RepositoryArchived(_, _))
    ));
    assert!(matches!(
        store.rename_repository(
            "alice",
            "renamed",
            "again",
            32,
            "admin-cli",
            "test-rename-fail"
        ),
        Err(StoreError::RepositoryArchived(_, _))
    ));
}

#[test]
fn runs_the_issue_workflow_with_atomic_events_and_repository_roles() {
    let directory = TempDir::new().expect("create an issue fixture directory");
    let mut store = Store::open(&database(&directory, "issues.sqlite")).expect("open the store");
    store
        .create_initial_administrator(&InitialAdministrator {
            username: "alice",
            canonical_key: "ssh-ed25519 AAAAalice",
            fingerprint: "SHA256:alice",
            recovery_hash: &[7; 32],
            created_at: 1,
        })
        .expect("create the repository owner");
    store
        .connection()
        .execute_batch(
            "INSERT INTO account (id, username, is_administrator, state, created_at) VALUES
                 (2, 'bob', 0, 'active', 1),
                 (3, 'carol', 0, 'active', 1),
                 (4, 'maintainer', 0, 'active', 1),
                 (5, 'stranger', 0, 'active', 1),
                 (6, 'suspended', 0, 'suspended', 1);",
        )
        .expect("create issue actors");
    store
        .create_repository(&NewRepository {
            id: "00112233445566778899aabbccddeeff",
            owner: "alice",
            slug: "project",
            object_format: "sha1",
            created_at: 2,
            origin: RepositoryOrigin::Created,
            initial_references: &[],
            actor: "alice",
            correlation_id: "issue-repository",
        })
        .expect("create an issue repository");
    store
        .connection()
        .execute_batch(
            "UPDATE repository SET visibility = 'private';
             INSERT INTO repository_collaborator
                 (repository_id, account_id, role, created_at)
             VALUES
                 ('00112233445566778899aabbccddeeff', 2, 'reader', 3),
                 ('00112233445566778899aabbccddeeff', 3, 'writer', 3),
                 ('00112233445566778899aabbccddeeff', 4, 'maintainer', 3);",
        )
        .expect("configure issue roles");

    let source = "Use **the supplied Markdown**.\n\n<script>do not run</script>";
    let issue = store
        .create_issue(&NewIssue {
            owner: "alice",
            repository: "project",
            actor: "bob",
            title: "Preserve Markdown",
            body: source,
            created_at: 4,
        })
        .expect("create an issue as a reader");
    assert_eq!(issue.number, 1);
    assert_eq!(issue.body, source);
    let second = store
        .create_issue(&NewIssue {
            owner: "alice",
            repository: "project",
            actor: "carol",
            title: "Second issue",
            body: "",
            created_at: 5,
        })
        .expect("allocate the next issue number");
    assert_eq!(second.number, 2);
    assert!(matches!(
        store.issues("alice", "project", None),
        Err(StoreError::IssueHidden)
    ));
    assert_eq!(
        store
            .issues("alice", "project", Some("bob"))
            .expect("list private issues as a reader")
            .1
            .len(),
        2
    );
    let change = |actor, changed_at| IssueChange {
        owner: "alice",
        repository: "project",
        number: 1,
        actor,
        changed_at,
    };
    assert!(matches!(
        store.edit_issue(
            &IssueChange {
                number: 2,
                ..change("bob", 6)
            },
            "Reader edit",
            "denied",
        ),
        Err(StoreError::IssueDenied)
    ));
    store
        .edit_issue(&change("bob", 7), "Preserve the source", source)
        .expect("edit an authored issue");
    store
        .edit_issue(&change("carol", 8), "Writer edit", source)
        .expect("edit an issue as a writer");
    let comment_id = store
        .comment_issue(
            "alice",
            "project",
            1,
            "bob",
            "A comment with [text](https://example.com).",
            9,
        )
        .expect("comment as a reader");
    assert_eq!(comment_id.len(), 32);
    assert!(matches!(
        store.set_issue_label(&change("bob", 10), "bug", true),
        Err(StoreError::IssueDenied)
    ));
    store
        .set_issue_label(&change("maintainer", 11), "bug", true)
        .expect("label as a maintainer");
    store
        .set_issue_assignee(&change("maintainer", 12), "bob", true)
        .expect("assign a repository reader");
    assert!(matches!(
        store.set_issue_assignee(&change("maintainer", 13), "stranger", true),
        Err(StoreError::IssueAssigneeNotFound(username)) if username == "stranger"
    ));
    store
        .set_issue_state("alice", "project", 1, "bob", "closed", 14)
        .expect("close an authored issue");
    store
        .set_issue_state("alice", "project", 1, "carol", "open", 15)
        .expect("reopen an issue as a writer");

    let detail = store
        .issue_detail("alice", "project", 1, Some("maintainer"))
        .expect("read the issue timeline");
    assert_eq!(detail.repository.slug, "project");
    assert_eq!(detail.issue.title, "Writer edit");
    assert_eq!(detail.issue.body, source);
    assert_eq!(detail.issue.state, "open");
    assert_eq!(detail.comments.len(), 1);
    assert_eq!(detail.labels, ["bug"]);
    assert_eq!(detail.assignees, ["bob"]);
    assert!(detail.can_comment);
    assert!(detail.can_edit);
    assert!(detail.can_maintain);
    assert_eq!(
        detail
            .timeline
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        [
            "issue-created",
            "issue-edited",
            "issue-edited",
            "issue-commented",
            "issue-labeled",
            "issue-assigned",
            "issue-closed",
            "issue-reopened",
        ]
    );
    assert!(
        detail
            .timeline
            .windows(2)
            .all(|events| events[0].sequence < events[1].sequence)
    );
    for event in &detail.timeline {
        let payload: serde_json::Value =
            serde_json::from_str(&event.payload).expect("parse an issue event payload");
        assert_eq!(payload["version"], 1);
        assert_eq!(payload["issue_id"], issue.id);
        assert!(event.created_at >= 4);
        assert!(!event.actor.is_empty());
    }

    let comments_before: i64 = store
        .connection()
        .query_row("SELECT count(*) FROM issue_comment", [], |row| row.get(0))
        .expect("count issue comments");
    store
        .connection()
        .execute_batch(
            "CREATE TEMP TRIGGER reject_issue_event
             BEFORE INSERT ON repository_event
             BEGIN
                 SELECT RAISE(ABORT, 'injected issue event failure');
             END;",
        )
        .expect("inject an issue event failure");
    assert!(matches!(
        store.comment_issue("alice", "project", 1, "bob", "must roll back", 16),
        Err(StoreError::Sqlite(_))
    ));
    assert_eq!(
        store
            .connection()
            .query_row("SELECT count(*) FROM issue_comment", [], |row| row
                .get::<_, i64>(0))
            .expect("count comments after rollback"),
        comments_before
    );
}

#[test]
fn enforces_constraints_and_supports_crud_and_indexed_scans() {
    let directory = TempDir::new().expect("create a temporary directory");
    let mut store = Store::open(&database(&directory, "store.sqlite")).expect("open the store");
    let connection = store.connection_mut();

    connection
        .execute(
            "INSERT INTO m1a_parent (id, name, created_at) VALUES (?1, ?2, ?3)",
            params![1, "parent", 10],
        )
        .expect("insert a parent");
    connection
        .execute(
            "INSERT INTO m1a_child (id, parent_id, sequence, body) VALUES (?1, ?2, ?3, ?4)",
            params![1, 1, 1, "body"],
        )
        .expect("insert a child");

    let duplicate = connection
        .execute(
            "INSERT INTO m1a_parent (id, name, created_at) VALUES (?1, ?2, ?3)",
            params![2, "parent", 11],
        )
        .expect_err("reject a duplicate name");
    assert_eq!(
        duplicate.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    );

    let orphan = connection
        .execute(
            "INSERT INTO m1a_child (id, parent_id, sequence, body) VALUES (?1, ?2, ?3, ?4)",
            params![2, 999, 1, "orphan"],
        )
        .expect_err("reject an orphan");
    assert_eq!(
        orphan.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    );

    let deletion = connection
        .execute("DELETE FROM m1a_parent WHERE id = ?1", [1])
        .expect_err("restrict deletion of a referenced parent");
    assert_eq!(
        deletion.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    );

    connection
        .execute(
            "UPDATE m1a_child SET body = ?1, state = ?2 WHERE id = ?3",
            params!["changed", "closed", 1],
        )
        .expect("update a child");
    let child: (String, String) = connection
        .query_row(
            "SELECT body, state FROM m1a_child WHERE id = ?1",
            [1],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read the child");
    assert_eq!(child, ("changed".to_owned(), "closed".to_owned()));

    let plan: String = connection
        .query_row(
            "EXPLAIN QUERY PLAN SELECT id FROM m1a_parent WHERE created_at >= ?1 ORDER BY created_at, id",
            [0],
            |row| row.get(3),
        )
        .expect("read the query plan");
    assert!(plan.contains("m1a_parent_created_at"), "query plan: {plan}");

    connection
        .execute("DELETE FROM m1a_child WHERE id = ?1", [1])
        .expect("delete the child");
    connection
        .execute("DELETE FROM m1a_parent WHERE id = ?1", [1])
        .expect("delete the parent");
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM m1a_parent", [], |row| row
                .get::<_, i64>(0))
            .expect("count parents"),
        0
    );
}

#[test]
fn rolls_back_a_failed_unit_of_work() {
    let directory = TempDir::new().expect("create a temporary directory");
    let mut store = Store::open(&database(&directory, "store.sqlite")).expect("open the store");

    let transaction = store
        .connection_mut()
        .transaction()
        .expect("start a transaction");
    transaction
        .execute(
            "INSERT INTO m1a_parent (id, name, created_at) VALUES (?1, ?2, ?3)",
            params![1, "rolled-back", 1],
        )
        .expect("insert a parent");
    transaction.rollback().expect("roll back the transaction");

    assert_eq!(
        store
            .connection()
            .query_row("SELECT count(*) FROM m1a_parent", [], |row| row
                .get::<_, i64>(0))
            .expect("count parents"),
        0
    );
}

#[test]
fn recovers_committed_state_and_discards_uncommitted_state_after_a_process_kill() {
    for (mode, expected_rows) in [("write-uncommitted", 0), ("write-committed", 1)] {
        let directory = TempDir::new().expect("create a temporary directory");
        let path = database(&directory, "store.sqlite");
        Store::open(&path).expect("create the store");
        let ready_path = database(&directory, "ready");

        let child = spawn_crash_child(mode, &path, &ready_path);
        kill_child(child, &ready_path);

        let store = Store::open(&path).expect("recover the store");
        store.integrity_check().expect("check recovered integrity");
        assert_eq!(
            store
                .connection()
                .query_row("SELECT count(*) FROM m1a_parent", [], |row| row
                    .get::<_, i64>(0))
                .expect("count recovered rows"),
            expected_rows,
            "recovered row count for {mode}"
        );
    }
}

#[test]
fn permits_reads_during_a_write_and_serializes_writers() {
    let directory = TempDir::new().expect("create a temporary directory");
    let path = database(&directory, "store.sqlite");
    let store = Store::open(&path).expect("open the store");
    store
        .connection()
        .execute(
            "INSERT INTO m1a_parent (id, name, created_at) VALUES (1, 'initial', 1)",
            [],
        )
        .expect("insert the initial parent");
    drop(store);

    let (locked_sender, locked_receiver) = mpsc::channel();
    let writer_path = path.clone();
    let writer = thread::spawn(move || {
        let mut store = Store::open(&writer_path).expect("open the first writer");
        let transaction = store
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start the first write");
        transaction
            .execute(
                "INSERT INTO m1a_parent (id, name, created_at) VALUES (2, 'first-writer', 2)",
                [],
            )
            .expect("write with the first writer");
        locked_sender.send(()).expect("signal the write lock");
        thread::sleep(Duration::from_millis(200));
        transaction.commit().expect("commit the first writer");
    });

    locked_receiver.recv().expect("wait for the write lock");
    let reader = Store::open(&path).expect("open a reader");
    assert_eq!(
        reader
            .connection()
            .query_row("SELECT count(*) FROM m1a_parent", [], |row| row
                .get::<_, i64>(0))
            .expect("read during a write"),
        1
    );
    drop(reader);

    let started = Instant::now();
    let second_writer = Store::open(&path).expect("open the second writer");
    second_writer
        .connection()
        .execute(
            "INSERT INTO m1a_parent (id, name, created_at) VALUES (3, 'second-writer', 3)",
            [],
        )
        .expect("write with the second writer");
    assert!(started.elapsed() >= Duration::from_millis(100));
    writer.join().expect("join the first writer");

    assert_eq!(
        second_writer
            .connection()
            .query_row("SELECT count(*) FROM m1a_parent", [], |row| row
                .get::<_, i64>(0))
            .expect("count committed writes"),
        3
    );
}

#[test]
fn returns_busy_after_the_configured_timeout() {
    let directory = TempDir::new().expect("create a temporary directory");
    let path = database(&directory, "store.sqlite");
    let mut first = Store::open(&path).expect("open the first store");
    let second = Store::open(&path).expect("open the second store");
    second
        .connection()
        .busy_timeout(Duration::from_millis(50))
        .expect("set a short busy timeout");

    let transaction = first
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start a write transaction");
    transaction
        .execute(
            "INSERT INTO m1a_parent (id, name, created_at) VALUES (1, 'locked', 1)",
            [],
        )
        .expect("hold the write lock");

    let started = Instant::now();
    let error = second
        .connection()
        .execute(
            "INSERT INTO m1a_parent (id, name, created_at) VALUES (2, 'busy', 2)",
            [],
        )
        .expect_err("return a busy error");
    assert_eq!(error.sqlite_error_code(), Some(ErrorCode::DatabaseBusy));
    assert!(started.elapsed() >= Duration::from_millis(40));
    transaction.rollback().expect("release the write lock");
}

#[test]
fn backs_up_a_consistent_database_while_writes_continue() {
    let directory = TempDir::new().expect("create a temporary directory");
    let source_path = database(&directory, "source.sqlite");
    let backup_path = database(&directory, "backup.sqlite");
    let source = Store::open(&source_path).expect("open the source store");
    source
        .connection()
        .execute(
            "INSERT INTO m1a_parent (id, name, created_at) VALUES (1, 'parent', 1)",
            [],
        )
        .expect("insert the parent");
    for sequence in 0..1_000 {
        source
            .connection()
            .execute(
                "INSERT INTO m1a_child (id, parent_id, sequence, body) VALUES (?1, 1, ?2, 'initial')",
                params![sequence + 1, sequence],
            )
            .expect("insert an initial child");
    }

    let running = Arc::new(AtomicBool::new(true));
    let writer_running = Arc::clone(&running);
    let writer_path = source_path.clone();
    let writer = thread::spawn(move || {
        let store = Store::open(&writer_path).expect("open the backup writer");
        let mut sequence = 1_000;
        while writer_running.load(Ordering::Relaxed) {
            store
                .connection()
                .execute(
                    "INSERT INTO m1a_child (id, parent_id, sequence, body) VALUES (?1, 1, ?2, 'concurrent')",
                    params![sequence + 1, sequence],
                )
                .expect("insert a concurrent child");
            sequence += 1;
        }
        sequence
    });

    let reader_running = Arc::clone(&running);
    let reader_path = source_path.clone();
    let (reader_ready_sender, reader_ready_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let store = Store::open(&reader_path).expect("open the backup reader");
        let mut read_count = 0;
        while reader_running.load(Ordering::Relaxed) {
            let _: i64 = store
                .connection()
                .query_row("SELECT count(*) FROM m1a_child", [], |row| row.get(0))
                .expect("read while the backup runs");
            if read_count == 0 {
                reader_ready_sender
                    .send(())
                    .expect("signal that the reader is ready");
            }
            read_count += 1;
        }
        read_count
    });
    reader_ready_receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("wait for the backup reader");

    source
        .backup(&backup_path)
        .expect("create an online backup");
    running.store(false, Ordering::Relaxed);
    let final_sequence = writer.join().expect("join the backup writer");
    let read_count = reader.join().expect("join the backup reader");
    assert!(read_count > 0);
    let backup = Store::open(&backup_path).expect("open the backup");
    backup.integrity_check().expect("check backup integrity");
    let backup_count: i64 = backup
        .connection()
        .query_row("SELECT count(*) FROM m1a_child", [], |row| row.get(0))
        .expect("count backup children");
    assert!(backup_count >= 1_000);
    assert!(backup_count <= i64::from(final_sequence));
}

#[test]
fn migrates_each_committed_historical_fixture() {
    for (fixture, initial_version) in [
        (V1_FIXTURE, 1),
        (V2_FIXTURE, 2),
        (V3_FIXTURE, 3),
        (V4_FIXTURE, 4),
        (V5_FIXTURE, 5),
        (V6_FIXTURE, 6),
        (V7_FIXTURE, 7),
        (V8_FIXTURE, 8),
        (V9_FIXTURE, 9),
        (V10_FIXTURE, 10),
        (V11_FIXTURE, 11),
    ] {
        let directory = TempDir::new().expect("create a temporary directory");
        let path = database(&directory, "tit.sqlite3");
        create_fixture(&path, fixture);

        let store = Store::open(&path).expect("migrate the fixture");
        assert_eq!(store.schema_version().expect("read the schema version"), 12);
        store.integrity_check().expect("check migrated integrity");
        let state: String = store
            .connection()
            .query_row("SELECT state FROM m1a_child WHERE id = 1", [], |row| {
                row.get(0)
            })
            .expect("read the migrated state");
        let expected = if initial_version == 1 {
            "open"
        } else {
            "closed"
        };
        assert_eq!(state, expected);
        store::doctor(directory.path()).expect("check the migrated fixture with doctor");

        let backup_path = migration_backup(&path, initial_version);
        assert!(backup_path.exists());
        let backup = Store::open_unmigrated(&backup_path).expect("open the migration backup");
        assert_eq!(
            backup.schema_version().expect("read the backup version"),
            initial_version
        );
        backup.integrity_check().expect("check backup integrity");
    }
}

#[test]
fn backfills_repository_events_when_version_five_is_migrated() {
    let directory = TempDir::new().expect("create a temporary directory");
    let path = database(&directory, "tit.sqlite3");
    create_fixture(&path, V5_FIXTURE);
    let connection = Connection::open(&path).expect("open the version-five fixture");
    connection
        .execute(
            "INSERT INTO account
             (id, username, is_administrator, state, created_at)
             VALUES (1, 'alice', 1, 'active', 1)",
            [],
        )
        .expect("insert a historical account");
    connection
        .execute(
            "INSERT INTO repository
             (id, owner_account_id, slug, visibility, state, object_format, created_at)
             VALUES ('00112233445566778899aabbccddeeff', 1, 'project', 'public',
                     'active', 'sha1', 2)",
            [],
        )
        .expect("insert a historical repository");
    connection
        .pragma_update(None, "user_version", 5)
        .expect("set the historical schema version");
    drop(connection);

    let store = Store::open(&path).expect("migrate the version-five fixture");
    let (_, events) = store
        .public_repository_events("alice", "project", None, 10)
        .expect("read the backfilled event");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "repository-created");
    assert_eq!(events[0].sequence, 1);
    assert_eq!(events[0].payload_version, 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&events[0].payload)
            .expect("parse the backfilled event payload")["version"],
        1
    );
    assert_eq!(events[0].created_at, 2);
}

#[test]
fn recovers_complete_schema_versions_after_a_process_kill_during_migration() {
    for (mode, expected_version) in [("migration-uncommitted", 1), ("migration-committed", 12)] {
        let directory = TempDir::new().expect("create a temporary directory");
        let path = database(&directory, "fixture.sqlite");
        create_fixture(&path, V1_FIXTURE);
        let ready_path = database(&directory, "ready");

        let child = spawn_crash_child(mode, &path, &ready_path);
        kill_child(child, &ready_path);

        let store = Store::open_unmigrated(&path).expect("recover the fixture");
        assert_eq!(
            store.schema_version().expect("read the recovered version"),
            expected_version,
            "recovered schema version for {mode}"
        );
        store.integrity_check().expect("check recovered integrity");

        let has_state: i64 = store
            .connection()
            .query_row(
                "SELECT count(*) FROM pragma_table_info('m1a_child') WHERE name = 'state'",
                [],
                |row| row.get(0),
            )
            .expect("inspect the recovered schema");
        assert_eq!(has_state, i64::from(expected_version >= 2));
    }
}

#[test]
fn rejects_a_newer_schema() {
    let directory = TempDir::new().expect("create a temporary directory");
    let path = database(&directory, "newer.sqlite");
    let connection = Connection::open(&path).expect("open a fixture database");
    connection
        .pragma_update(None, "user_version", 999)
        .expect("set a newer version");
    drop(connection);

    assert!(matches!(
        Store::open(&path),
        Err(StoreError::NewerSchema(999))
    ));
}

#[test]
fn checkpoints_and_vacuums_without_losing_data() {
    let directory = TempDir::new().expect("create a temporary directory");
    let path = database(&directory, "store.sqlite");
    let store = Store::open(&path).expect("open the store");
    store
        .connection()
        .execute(
            "INSERT INTO m1a_parent (id, name, created_at) VALUES (1, 'parent', 1)",
            [],
        )
        .expect("insert a parent");

    store.checkpoint().expect("checkpoint the WAL");
    store.vacuum().expect("vacuum the database");
    store.integrity_check().expect("check database integrity");
    assert_eq!(
        store
            .connection()
            .query_row("SELECT count(*) FROM m1a_parent", [], |row| row
                .get::<_, i64>(0))
            .expect("count parents"),
        1
    );
}
