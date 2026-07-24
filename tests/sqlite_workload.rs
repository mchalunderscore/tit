#[allow(
    dead_code,
    reason = "the M1A workload does not use Git operation intents"
)]
#[path = "../src/store/mod.rs"]
mod store;

use std::fs;
use std::time::{Duration, Instant};

use rusqlite::{Connection, params};
use store::Store;
use tempfile::TempDir;

const V1_FIXTURE: &str = include_str!("fixtures/sqlite/v1.sql");
const ISSUE_COUNT: i64 = 10_000;
const EVENTS_PER_ISSUE: i64 = 100;
const EVENT_COUNT: i64 = ISSUE_COUNT * EVENTS_PER_ISSUE;
const MAX_DATABASE_BYTES: u64 = 1_073_741_824;
const MAX_OPERATION_TIME: Duration = Duration::from_secs(120);
const MAX_P99_QUERY_TIME: Duration = Duration::from_millis(250);

#[test]
#[ignore = "run this workload explicitly"]
fn measures_the_m1a_workload() {
    let directory = TempDir::new().expect("create a temporary directory");
    let database_path = directory.path().join("workload.sqlite");
    let backup_path = directory.path().join("workload.backup.sqlite");
    create_version_one_workload(&database_path);

    let migration_started = Instant::now();
    let store = Store::open(&database_path).expect("back up and migrate the workload");
    let migration_time = migration_started.elapsed();
    store.checkpoint().expect("checkpoint the workload");
    let database_bytes = fs::metadata(&database_path)
        .expect("inspect the workload database")
        .len();

    let query_times = measure_queries(&store);
    let p50_query_time = percentile(&query_times, 50);
    let p95_query_time = percentile(&query_times, 95);
    let p99_query_time = percentile(&query_times, 99);

    let backup_started = Instant::now();
    store.backup(&backup_path).expect("back up the workload");
    let backup_time = backup_started.elapsed();
    let restored = Store::open(&backup_path).expect("restore the workload backup");
    restored
        .integrity_check()
        .expect("check restored workload integrity");
    let restored_counts: (i64, i64) = restored
        .connection()
        .query_row(
            "SELECT (SELECT count(*) FROM m1a_parent), \
                    (SELECT count(*) FROM m1a_child)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("count restored workload records");
    assert_eq!(restored_counts, (ISSUE_COUNT, EVENT_COUNT));

    eprintln!(
        "M1A workload: database_bytes={database_bytes} migration_ms={} backup_ms={} query_p50_us={} query_p95_us={} query_p99_us={}",
        migration_time.as_millis(),
        backup_time.as_millis(),
        p50_query_time.as_micros(),
        p95_query_time.as_micros(),
        p99_query_time.as_micros()
    );

    assert!(database_bytes <= MAX_DATABASE_BYTES);
    assert!(migration_time <= MAX_OPERATION_TIME);
    assert!(backup_time <= MAX_OPERATION_TIME);
    assert!(p99_query_time <= MAX_P99_QUERY_TIME);
}

fn create_version_one_workload(path: &std::path::Path) {
    let mut connection = Connection::open(path).expect("open the workload database");
    connection
        .execute_batch(V1_FIXTURE)
        .expect("create the version-one schema");
    connection
        .execute_batch("DELETE FROM m1a_child; DELETE FROM m1a_parent;")
        .expect("remove the small fixture records");
    connection
        .pragma_update(None, "foreign_keys", true)
        .expect("enable foreign keys");

    let transaction = connection.transaction().expect("start the workload");
    {
        let mut insert_issue = transaction
            .prepare("INSERT INTO m1a_parent (id, name, created_at) VALUES (?1, ?2, ?3)")
            .expect("prepare the issue insert");
        let mut insert_event = transaction
            .prepare(
                "INSERT INTO m1a_child (id, parent_id, sequence, body) VALUES (?1, ?2, ?3, ?4)",
            )
            .expect("prepare the event insert");
        let body = "A representative issue event records a bounded plain-text change.";

        for issue_id in 1..=ISSUE_COUNT {
            insert_issue
                .execute(params![issue_id, format!("issue-{issue_id}"), issue_id])
                .expect("insert an issue");
            for sequence in 0..EVENTS_PER_ISSUE {
                let event_id = (issue_id - 1) * EVENTS_PER_ISSUE + sequence + 1;
                insert_event
                    .execute(params![event_id, issue_id, sequence, body])
                    .expect("insert an event");
            }
        }
    }
    transaction.commit().expect("commit the workload");
}

fn measure_queries(store: &Store) -> Vec<Duration> {
    let mut times = Vec::with_capacity(1_000);
    let mut statement = store
        .connection()
        .prepare(
            "SELECT id, sequence, body FROM m1a_child \
             WHERE state = ?1 AND parent_id = ?2 ORDER BY sequence LIMIT 25",
        )
        .expect("prepare the representative query");

    for sample in 0_i64..1_000 {
        let issue_id = sample % ISSUE_COUNT + 1;
        let started = Instant::now();
        let mut rows = statement
            .query(params!["open", issue_id])
            .expect("query issue events");
        let mut row_count = 0;
        while let Some(row) = rows.next().expect("read an issue event") {
            let _: (i64, i64, String) = (
                row.get(0).expect("read the event ID"),
                row.get(1).expect("read the sequence"),
                row.get(2).expect("read the body"),
            );
            row_count += 1;
        }
        assert_eq!(row_count, 25);
        times.push(started.elapsed());
    }
    times.sort_unstable();
    times
}

fn percentile(times: &[Duration], percentile: usize) -> Duration {
    times[(times.len() - 1) * percentile / 100]
}
