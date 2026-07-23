use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::OpenFlags;
use rusqlite::backup::Backup;
use rusqlite::{Connection, TransactionBehavior};
use thiserror::Error;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const BUSY_TIMEOUT_MILLISECONDS: i64 = 5_000;
const SCHEMA_VERSION: i64 = 3;
#[allow(
    dead_code,
    reason = "the integration test imports this module without the CLI operation"
)]
const DATABASE_FILE: &str = "tit.sqlite3";
#[allow(
    dead_code,
    reason = "M1A proves migrations before the M2 server calls them"
)]
const MIGRATIONS: [&str; 3] = [
    include_str!("migrations/001_initial.sql"),
    include_str!("migrations/002_state.sql"),
    include_str!("migrations/003_git_intents.sql"),
];

#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[allow(
        dead_code,
        reason = "M1A proves migrations before the M2 server calls them"
    )]
    #[error("database schema version {0} is newer than this executable")]
    NewerSchema(i64),
    #[allow(
        dead_code,
        reason = "the integration test imports this module without the CLI operation"
    )]
    #[error("database schema version is {actual}, expected {expected}")]
    SchemaVersion { expected: i64, actual: i64 },
    #[error("database integrity check failed: {0}")]
    Integrity(String),
    #[error("SQLite setting {name} is {actual}, expected {expected}")]
    Setting {
        name: &'static str,
        expected: &'static str,
        actual: String,
    },
    #[error("Git operation intent {0} is not in the required state")]
    IntentState(String),
}

pub(crate) struct Store {
    connection: Connection,
}

impl Store {
    #[allow(
        dead_code,
        reason = "M1A proves migrations before the M2 server calls them"
    )]
    pub(crate) fn open(path: &Path) -> Result<Self, StoreError> {
        let mut store = Self::open_unmigrated(path)?;
        let current = store.schema_version()?;
        if current > 0 && current < SCHEMA_VERSION {
            store.backup(&migration_backup_path(path, current))?;
        }
        store.migrate()?;
        Ok(store)
    }

    #[allow(
        dead_code,
        reason = "M1A proves migrations before the M2 server calls them"
    )]
    pub(crate) fn open_unmigrated(path: &Path) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        configure(&connection)?;
        Ok(Self { connection })
    }

    #[allow(
        dead_code,
        reason = "M1A proves migrations before the M2 server calls them"
    )]
    pub(crate) fn migrate(&mut self) -> Result<(), StoreError> {
        self.migrate_with_hook(|_| {})
    }

    #[allow(
        dead_code,
        reason = "M1A proves migrations before the M2 server calls them"
    )]
    pub(crate) fn migrate_with_hook(
        &mut self,
        mut after_migration: impl FnMut(i64),
    ) -> Result<(), StoreError> {
        let current = self.schema_version()?;
        if current > SCHEMA_VERSION {
            return Err(StoreError::NewerSchema(current));
        }
        if current == SCHEMA_VERSION {
            return Ok(());
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;
        for version in (current + 1)..=SCHEMA_VERSION {
            transaction.execute_batch(MIGRATIONS[(version - 1) as usize])?;
            transaction.pragma_update(None, "user_version", version)?;
            after_migration(version);
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn schema_version(&self) -> Result<i64, StoreError> {
        Ok(self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    pub(crate) fn integrity_check(&self) -> Result<(), StoreError> {
        let result: String =
            self.connection
                .pragma_query_value(None, "integrity_check", |row| row.get(0))?;
        if result != "ok" {
            return Err(StoreError::Integrity(result));
        }

        let mut statement = self.connection.prepare("PRAGMA foreign_key_check")?;
        let mut rows = statement.query([])?;
        if let Some(row) = rows.next()? {
            let table: String = row.get(0)?;
            return Err(StoreError::Integrity(format!(
                "foreign key violation in table {table}"
            )));
        }
        Ok(())
    }

    #[allow(dead_code, reason = "M1A proves backup before the M2 server calls it")]
    pub(crate) fn backup(&self, path: &Path) -> Result<(), StoreError> {
        let mut destination = Connection::open(path)?;
        let backup = Backup::new(&self.connection, &mut destination)?;
        backup.run_to_completion(128, Duration::from_millis(1), None)?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "M1A proves maintenance before an operator command calls it"
    )]
    pub(crate) fn checkpoint(&self) -> Result<(), StoreError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "M1A proves maintenance before an operator command calls it"
    )]
    pub(crate) fn vacuum(&self) -> Result<(), StoreError> {
        self.connection.execute_batch("VACUUM")?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "M1A tests storage behavior through this narrow test boundary"
    )]
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    #[allow(
        dead_code,
        reason = "M1A tests storage behavior through this narrow test boundary"
    )]
    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub(crate) fn begin_git_intent(
        &self,
        intent: &GitOperationIntent<'_>,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO git_operation_intent
             (id, repository_path, actor, initial_refs, proposed_refs, event_payload,
              quarantine_path, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8)",
            rusqlite::params![
                intent.id,
                intent.repository_path,
                intent.actor,
                intent.initial_refs,
                intent.proposed_refs,
                intent.event_payload,
                intent.quarantine_path,
                intent.created_at,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn mark_git_objects_promoted(
        &self,
        id: &str,
        pack_name: Option<&str>,
    ) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE git_operation_intent
             SET state = 'promoted', pack_name = ?2
             WHERE id = ?1 AND state = 'pending'",
            rusqlite::params![id, pack_name],
        )?;
        require_one_intent(id, changed)
    }

    pub(crate) fn complete_git_intent(&mut self, id: &str) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let payload: Vec<u8> = transaction.query_row(
            "SELECT event_payload FROM git_operation_intent
             WHERE id = ?1 AND state = 'promoted'",
            [id],
            |row| row.get(0),
        )?;
        let changed = transaction.execute(
            "UPDATE git_operation_intent SET state = 'completed'
             WHERE id = ?1 AND state = 'promoted'",
            [id],
        )?;
        require_one_intent(id, changed)?;
        transaction.execute(
            "INSERT INTO git_operation_event (intent_id, payload) VALUES (?1, ?2)",
            rusqlite::params![id, payload],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn abandon_git_intent(&self, id: &str) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE git_operation_intent SET state = 'abandoned'
             WHERE id = ?1 AND state IN ('pending', 'promoted')",
            [id],
        )?;
        require_one_intent(id, changed)
    }

    pub(crate) fn incomplete_git_intents(&self) -> Result<Vec<GitIntentRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, repository_path, initial_refs, proposed_refs, quarantine_path,
                    state, pack_name
             FROM git_operation_intent
             WHERE state IN ('pending', 'promoted')
             ORDER BY created_at, id",
        )?;
        let records = statement
            .query_map([], |row| {
                Ok(GitIntentRecord {
                    id: row.get(0)?,
                    repository_path: row.get(1)?,
                    initial_refs: row.get(2)?,
                    proposed_refs: row.get(3)?,
                    quarantine_path: row.get(4)?,
                    state: row.get(5)?,
                    pack_name: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }
}

pub(crate) struct GitOperationIntent<'a> {
    pub(crate) id: &'a str,
    pub(crate) repository_path: &'a str,
    pub(crate) actor: &'a str,
    pub(crate) initial_refs: &'a [u8],
    pub(crate) proposed_refs: &'a [u8],
    pub(crate) event_payload: &'a [u8],
    pub(crate) quarantine_path: &'a str,
    pub(crate) created_at: i64,
}

pub(crate) struct GitIntentRecord {
    pub(crate) id: String,
    pub(crate) repository_path: String,
    pub(crate) initial_refs: Vec<u8>,
    pub(crate) proposed_refs: Vec<u8>,
    pub(crate) quarantine_path: String,
    pub(crate) state: String,
    pub(crate) pack_name: Option<String>,
}

fn require_one_intent(id: &str, changed: usize) -> Result<(), StoreError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::IntentState(id.to_owned()))
    }
}

#[allow(
    dead_code,
    reason = "the integration test imports this module without the CLI operation"
)]
pub(crate) fn doctor(instance_dir: &Path) -> Result<(), StoreError> {
    let path = instance_dir.join(DATABASE_FILE);
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    configure(&connection)?;
    let store = Store { connection };
    let actual = store.schema_version()?;
    if actual != SCHEMA_VERSION {
        return Err(StoreError::SchemaVersion {
            expected: SCHEMA_VERSION,
            actual,
        });
    }
    store.integrity_check()
}

#[allow(
    dead_code,
    reason = "M1A proves migrations before the M2 server calls them"
)]
fn migration_backup_path(path: &Path, version: i64) -> PathBuf {
    let mut backup = OsString::from(path.as_os_str());
    backup.push(format!(".v{version}.backup"));
    PathBuf::from(backup)
}

fn configure(connection: &Connection) -> Result<(), StoreError> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", true)?;

    verify_text_setting(connection, "journal_mode", "wal")?;
    verify_integer_setting(connection, "synchronous", 2, "2")?;
    verify_integer_setting(connection, "foreign_keys", 1, "1")?;
    verify_integer_setting(
        connection,
        "busy_timeout",
        BUSY_TIMEOUT_MILLISECONDS,
        "5000",
    )?;
    Ok(())
}

fn verify_text_setting(
    connection: &Connection,
    name: &'static str,
    expected: &'static str,
) -> Result<(), StoreError> {
    let actual: String = connection.pragma_query_value(None, name, |row| row.get(0))?;
    if actual.eq_ignore_ascii_case(expected) {
        return Ok(());
    }
    Err(StoreError::Setting {
        name,
        expected,
        actual,
    })
}

fn verify_integer_setting(
    connection: &Connection,
    name: &'static str,
    expected: i64,
    expected_text: &'static str,
) -> Result<(), StoreError> {
    let actual: i64 = connection.pragma_query_value(None, name, |row| row.get(0))?;
    if actual == expected {
        return Ok(());
    }
    Err(StoreError::Setting {
        name,
        expected: expected_text,
        actual: actual.to_string(),
    })
}
