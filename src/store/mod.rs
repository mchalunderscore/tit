use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::OpenFlags;
use rusqlite::backup::Backup;
use rusqlite::{Connection, TransactionBehavior};
use thiserror::Error;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const BUSY_TIMEOUT_MILLISECONDS: i64 = 5_000;
const SCHEMA_VERSION: i64 = 2;
#[allow(
    dead_code,
    reason = "the integration test imports this module without the CLI operation"
)]
const DATABASE_FILE: &str = "tit.sqlite3";
#[allow(
    dead_code,
    reason = "M1A proves migrations before the M2 server calls them"
)]
const MIGRATIONS: [&str; 2] = [
    include_str!("migrations/001_initial.sql"),
    include_str!("migrations/002_state.sql"),
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
