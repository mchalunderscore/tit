#[path = "../src/store/mod.rs"]
mod store;

use std::process::{Child, Command};
use std::sync::mpsc;
use std::sync::{Arc, atomic::AtomicBool, atomic::Ordering};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, ffi::OsString, fs};

use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};
use store::{GitOperationIntent, Store, StoreError};
use tempfile::TempDir;

const V1_FIXTURE: &str = include_str!("fixtures/sqlite/v1.sql");
const V2_FIXTURE: &str = include_str!("fixtures/sqlite/v2.sql");

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

    assert_eq!(store.schema_version().expect("read the schema version"), 3);
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
    for (fixture, initial_version) in [(V1_FIXTURE, 1), (V2_FIXTURE, 2)] {
        let directory = TempDir::new().expect("create a temporary directory");
        let path = database(&directory, "tit.sqlite3");
        create_fixture(&path, fixture);

        let store = Store::open(&path).expect("migrate the fixture");
        assert_eq!(store.schema_version().expect("read the schema version"), 3);
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
fn recovers_complete_schema_versions_after_a_process_kill_during_migration() {
    for (mode, expected_version) in [("migration-uncommitted", 1), ("migration-committed", 3)] {
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
