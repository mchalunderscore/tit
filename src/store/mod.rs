use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::OpenFlags;
use rusqlite::backup::Backup;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use thiserror::Error;

mod event;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const BUSY_TIMEOUT_MILLISECONDS: i64 = 5_000;
const MAX_ACTIVE_FEED_TOKENS: i64 = 32;
const SCHEMA_VERSION: i64 = 15;
#[allow(
    dead_code,
    reason = "the integration test imports this module without the CLI operation"
)]
pub(crate) const DATABASE_FILE: &str = "tit.sqlite3";
#[allow(
    dead_code,
    reason = "M1A proves migrations before the M2 server calls them"
)]
const MIGRATIONS: [&str; 15] = [
    include_str!("migrations/001_initial.sql"),
    include_str!("migrations/002_state.sql"),
    include_str!("migrations/003_git_intents.sql"),
    include_str!("migrations/004_identity.sql"),
    include_str!("migrations/005_repository.sql"),
    include_str!("migrations/006_repository_events.sql"),
    include_str!("migrations/007_account_lifecycle.sql"),
    include_str!("migrations/008_web_sessions.sql"),
    include_str!("migrations/009_repository_authorization.sql"),
    include_str!("migrations/010_audit_history.sql"),
    include_str!("migrations/011_domain_events.sql"),
    include_str!("migrations/012_issues.sql"),
    include_str!("migrations/013_watches.sql"),
    include_str!("migrations/014_feed_tokens.sql"),
    include_str!("migrations/015_pull_requests.sql"),
];

#[allow(
    dead_code,
    reason = "integration tests compile storage without every account operation"
)]
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
    #[error("the instance already has an administrator")]
    AlreadyInitialized,
    #[error("account does not exist or is not active: {0}")]
    AccountNotFound(String),
    #[error("username is not available: {0}")]
    UsernameUnavailable(String),
    #[error("signup invitation is invalid, expired, or already used")]
    InvalidInvitation,
    #[error("recovery credential is invalid")]
    InvalidRecovery,
    #[error("SSH public key already exists")]
    KeyExists,
    #[error("active SSH public key does not exist")]
    KeyNotFound,
    #[error("an account must have at least one active SSH public key")]
    LastKey,
    #[error("login identity does not exist or is not active")]
    LoginIdentity,
    #[error("too many login challenges are active")]
    LoginNonceLimit,
    #[error("login challenge is invalid, expired, or already used")]
    InvalidLoginChallenge,
    #[error("Web session is invalid or expired")]
    InvalidSession,
    #[error("repository does not exist: {0}/{1}")]
    RepositoryNotFound(String, String),
    #[error("repository already exists: {0}/{1}")]
    RepositoryExists(String, String),
    #[error("repository ID already exists")]
    RepositoryIdentifierCollision,
    #[error("repository is already archived: {0}/{1}")]
    RepositoryArchived(String, String),
    #[error("repository visibility is not valid")]
    InvalidRepositoryVisibility,
    #[error("collaborator role is not valid")]
    InvalidCollaboratorRole,
    #[error("repository owner cannot be a collaborator")]
    OwnerCollaborator,
    #[error("collaborator account does not exist or is not active: {0}")]
    CollaboratorNotFound(String),
    #[allow(
        dead_code,
        reason = "some integration tests import storage without public event pages"
    )]
    #[error("repository event page limit is too large")]
    EventLimit,
    #[error("stored Git reference event is malformed")]
    EventPayload,
    #[error("audit event page limit is too large")]
    AuditLimit,
    #[error("issue does not exist: {0}/{1}#{2}")]
    IssueNotFound(String, String, i64),
    #[error("issue access is not authorized")]
    IssueDenied,
    #[error("issue is hidden by repository access policy")]
    IssueHidden,
    #[error("issue state is already {0}")]
    IssueState(String),
    #[error("issue label already has the requested state")]
    IssueLabelState,
    #[error("issue assignee already has the requested state")]
    IssueAssigneeState,
    #[error("issue assignee does not exist or cannot read the repository: {0}")]
    IssueAssigneeNotFound(String),
    #[error("pull request does not exist: {0}/{1}#{2}")]
    PullRequestNotFound(String, String, i64),
    #[error("pull-request access is not authorized")]
    PullRequestDenied,
    #[error("pull request is hidden by repository access policy")]
    PullRequestHidden,
    #[error("pull request is not open")]
    PullRequestState,
    #[error("pull-request ref intent {0} is not in the required state")]
    PullRequestIntentState(String),
    #[error("repository watch access is not authorized")]
    WatchDenied,
    #[error("feed token access is not authorized")]
    FeedTokenDenied,
    #[error("feed token is invalid or revoked")]
    FeedTokenNotFound,
    #[error("an account cannot have more than 32 active feed tokens")]
    FeedTokenLimit,
    #[error("feed token scope is not valid")]
    InvalidFeedScope,
}

pub(crate) struct Store {
    connection: Connection,
}

impl Store {
    #[allow(
        dead_code,
        reason = "some integration tests compile storage without audited services"
    )]
    pub(crate) fn record_audit_event(&self, event: &NewAuditEvent<'_>) -> Result<(), StoreError> {
        insert_audit_event(&self.connection, event)?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without the audit CLI"
    )]
    pub(crate) fn audit_events(&self, limit: usize) -> Result<Vec<AuditEventRecord>, StoreError> {
        if limit == 0 || limit > 1_000 {
            return Err(StoreError::AuditLimit);
        }
        let limit = i64::try_from(limit).map_err(|_| StoreError::AuditLimit)?;
        let mut statement = self.connection.prepare(
            "SELECT id, action, actor, target, outcome, correlation_id, created_at
             FROM audit_event ORDER BY id DESC LIMIT ?1",
        )?;
        statement
            .query_map([limit], |row| {
                Ok(AuditEventRecord {
                    id: row.get(0)?,
                    action: row.get(1)?,
                    actor: row.get(2)?,
                    target: row.get(3)?,
                    outcome: row.get(4)?,
                    correlation_id: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

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
        let (payload, repository_path, actor, initial_refs, proposed_refs, created_at): (
            Vec<u8>,
            String,
            String,
            Vec<u8>,
            Vec<u8>,
            i64,
        ) = transaction.query_row(
            "SELECT event_payload, repository_path, actor, initial_refs, proposed_refs, created_at
             FROM git_operation_intent
             WHERE id = ?1 AND state = 'promoted'",
            [id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
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
        insert_push_events(
            &transaction,
            id,
            &repository_path,
            &actor,
            &initial_refs,
            &proposed_refs,
            created_at,
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

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without receive-pack"
    )]
    pub(crate) fn git_intent_completed(&self, id: &str) -> Result<bool, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT state = 'completed' FROM git_operation_intent WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(false))
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

    pub(crate) fn create_initial_administrator(
        &mut self,
        administrator: &InitialAdministrator<'_>,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let accounts: i64 =
            transaction.query_row("SELECT count(*) FROM account", [], |row| row.get(0))?;
        if accounts != 0 {
            return Err(StoreError::AlreadyInitialized);
        }
        transaction.execute(
            "INSERT INTO account
             (username, is_administrator, state, created_at)
             VALUES (?1, 1, 'active', ?2)",
            rusqlite::params![administrator.username, administrator.created_at],
        )?;
        let account_id = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO ssh_public_key
             (account_id, canonical_key, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                account_id,
                administrator.canonical_key,
                administrator.fingerprint,
                administrator.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO recovery_credential
             (account_id, credential_hash, created_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                account_id,
                administrator.recovery_hash,
                administrator.created_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without accounts"
    )]
    pub(crate) fn create_signup_invitation(
        &self,
        code_hash: &[u8; 32],
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO signup_invitation (code_hash, created_at, expires_at, consumed_at)
             VALUES (?1, ?2, ?3, NULL)",
            rusqlite::params![code_hash, created_at, expires_at],
        )?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without accounts"
    )]
    pub(crate) fn create_account_with_invitation(
        &mut self,
        account: &InvitedAccount<'_>,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let consumed = transaction.execute(
            "UPDATE signup_invitation SET consumed_at = ?2
             WHERE code_hash = ?1 AND consumed_at IS NULL AND expires_at >= ?2",
            rusqlite::params![account.invitation_hash, account.created_at],
        )?;
        if consumed != 1 {
            return Err(StoreError::InvalidInvitation);
        }
        let inserted = transaction.execute(
            "INSERT INTO account (username, is_administrator, state, created_at)
             VALUES (?1, 0, 'active', ?2)",
            rusqlite::params![account.username, account.created_at],
        );
        let account_id = match inserted {
            Ok(1) => transaction.last_insert_rowid(),
            Err(error) if is_unique_constraint(&error) => {
                return Err(StoreError::UsernameUnavailable(account.username.to_owned()));
            }
            Err(error) => return Err(error.into()),
            Ok(_) => unreachable!("an INSERT changes one row"),
        };
        insert_ssh_key(&transaction, account_id, &account.key, account.created_at)?;
        transaction.execute(
            "INSERT INTO recovery_credential (account_id, credential_hash, created_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![account_id, account.recovery_hash, account.created_at],
        )?;
        insert_audit_event(
            &transaction,
            &NewAuditEvent {
                action: "account.signup",
                actor: account.username,
                target: account.username,
                outcome: "success",
                correlation_id: account.correlation_id,
                created_at: account.created_at,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without accounts"
    )]
    pub(crate) fn recover_account(
        &mut self,
        recovery: &AccountRecovery<'_>,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account_id = transaction
            .query_row(
                "SELECT account.id FROM account
                 JOIN recovery_credential ON recovery_credential.account_id = account.id
                 WHERE account.username = ?1 AND account.state = 'active'
                   AND recovery_credential.credential_hash = ?2",
                rusqlite::params![recovery.username, recovery.old_recovery_hash],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(StoreError::InvalidRecovery)?;
        transaction.execute(
            "UPDATE ssh_public_key SET revoked_at = ?2
             WHERE account_id = ?1 AND revoked_at IS NULL",
            rusqlite::params![account_id, recovery.created_at],
        )?;
        let existing = transaction
            .query_row(
                "SELECT account_id FROM ssh_public_key WHERE fingerprint = ?1",
                [recovery.key.fingerprint],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        match existing {
            Some(owner) if owner == account_id => {
                transaction.execute(
                    "UPDATE ssh_public_key
                     SET canonical_key = ?2, label = ?3, revoked_at = NULL
                     WHERE account_id = ?1 AND fingerprint = ?4",
                    rusqlite::params![
                        account_id,
                        recovery.key.canonical_key,
                        recovery.key.label,
                        recovery.key.fingerprint,
                    ],
                )?;
            }
            Some(_) => return Err(StoreError::KeyExists),
            None => insert_ssh_key(&transaction, account_id, &recovery.key, recovery.created_at)?,
        }
        transaction.execute(
            "UPDATE recovery_credential
             SET credential_hash = ?2, created_at = ?3 WHERE account_id = ?1",
            rusqlite::params![account_id, recovery.new_recovery_hash, recovery.created_at],
        )?;
        end_sessions(&transaction, account_id, recovery.created_at)?;
        insert_audit_event(
            &transaction,
            &NewAuditEvent {
                action: "account.recover",
                actor: recovery.username,
                target: recovery.username,
                outcome: "success",
                correlation_id: recovery.correlation_id,
                created_at: recovery.created_at,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without accounts"
    )]
    pub(crate) fn add_account_key(
        &mut self,
        username: &str,
        key: &NewSshKey<'_>,
        created_at: i64,
        actor: &str,
        correlation_id: &str,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account_id = active_account_id(&transaction, username)?;
        insert_ssh_key(&transaction, account_id, key, created_at)?;
        end_sessions(&transaction, account_id, created_at)?;
        let target = format!("{username}:{}", key.fingerprint);
        insert_audit_event(
            &transaction,
            &NewAuditEvent {
                action: "key.add",
                actor,
                target: &target,
                outcome: "success",
                correlation_id,
                created_at,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without accounts"
    )]
    pub(crate) fn revoke_account_key(
        &mut self,
        username: &str,
        fingerprint: &str,
        revoked_at: i64,
        actor: &str,
        correlation_id: &str,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account_id = active_account_id(&transaction, username)?;
        let active: i64 = transaction.query_row(
            "SELECT count(*) FROM ssh_public_key WHERE account_id = ?1 AND revoked_at IS NULL",
            [account_id],
            |row| row.get(0),
        )?;
        if active <= 1 {
            return Err(StoreError::LastKey);
        }
        let changed = transaction.execute(
            "UPDATE ssh_public_key SET revoked_at = ?3
             WHERE account_id = ?1 AND fingerprint = ?2 AND revoked_at IS NULL",
            rusqlite::params![account_id, fingerprint, revoked_at],
        )?;
        if changed != 1 {
            return Err(StoreError::KeyNotFound);
        }
        end_sessions(&transaction, account_id, revoked_at)?;
        let target = format!("{username}:{fingerprint}");
        insert_audit_event(
            &transaction,
            &NewAuditEvent {
                action: "key.revoke",
                actor,
                target: &target,
                outcome: "success",
                correlation_id,
                created_at: revoked_at,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without accounts"
    )]
    pub(crate) fn suspend_account(
        &mut self,
        username: &str,
        suspended: bool,
        changed_at: i64,
        actor: &str,
        correlation_id: &str,
    ) -> Result<(), StoreError> {
        let state = if suspended { "suspended" } else { "active" };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE account SET state = ?2 WHERE username = ?1",
            rusqlite::params![username, state],
        )?;
        if changed != 1 {
            return Err(StoreError::AccountNotFound(username.to_owned()));
        }
        let account_id: i64 = transaction.query_row(
            "SELECT id FROM account WHERE username = ?1",
            [username],
            |row| row.get(0),
        )?;
        end_sessions(&transaction, account_id, changed_at)?;
        insert_audit_event(
            &transaction,
            &NewAuditEvent {
                action: if suspended {
                    "account.suspend"
                } else {
                    "account.resume"
                },
                actor,
                target: username,
                outcome: "success",
                correlation_id,
                created_at: changed_at,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without Web login"
    )]
    pub(crate) fn create_login_nonce(
        &mut self,
        nonce: &NewLoginNonce<'_>,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM login_nonce WHERE expires_at < ?1 OR consumed_at IS NOT NULL",
            [nonce.created_at],
        )?;
        let active: i64 =
            transaction.query_row("SELECT count(*) FROM login_nonce", [], |row| row.get(0))?;
        if active >= 1_024 {
            return Err(StoreError::LoginNonceLimit);
        }
        let key = transaction
            .query_row(
                "SELECT account.id, ssh_public_key.id
                 FROM account
                 JOIN ssh_public_key ON ssh_public_key.account_id = account.id
                 WHERE account.username = ?1 AND account.state = 'active'
                   AND ssh_public_key.fingerprint = ?2
                   AND ssh_public_key.revoked_at IS NULL",
                rusqlite::params![nonce.username, nonce.fingerprint],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .ok_or(StoreError::LoginIdentity)?;
        transaction.execute(
            "INSERT INTO login_nonce
             (nonce_hash, csrf_hash, account_id, ssh_public_key_id,
              created_at, expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            rusqlite::params![
                nonce.nonce_hash,
                nonce.csrf_hash,
                key.0,
                key.1,
                nonce.created_at,
                nonce.expires_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without Web login"
    )]
    pub(crate) fn consume_login_nonce(
        &mut self,
        login: &NewWebSession<'_>,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account_id = transaction
            .query_row(
                "SELECT login_nonce.account_id
                 FROM login_nonce
                 JOIN account ON account.id = login_nonce.account_id
                 JOIN ssh_public_key ON ssh_public_key.id = login_nonce.ssh_public_key_id
                 WHERE login_nonce.nonce_hash = ?1
                   AND login_nonce.consumed_at IS NULL AND login_nonce.expires_at >= ?2
                   AND account.username = ?3 AND account.state = 'active'
                   AND ssh_public_key.fingerprint = ?4 AND ssh_public_key.revoked_at IS NULL
                   AND login_nonce.csrf_hash = ?5",
                rusqlite::params![
                    login.nonce_hash,
                    login.created_at,
                    login.username,
                    login.fingerprint,
                    login.login_csrf_hash,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(StoreError::InvalidLoginChallenge)?;
        let changed = transaction.execute(
            "UPDATE login_nonce SET consumed_at = ?2
             WHERE nonce_hash = ?1 AND consumed_at IS NULL",
            rusqlite::params![login.nonce_hash, login.created_at],
        )?;
        if changed != 1 {
            return Err(StoreError::InvalidLoginChallenge);
        }
        transaction.execute(
            "INSERT INTO web_session
             (session_hash, csrf_hash, account_id, created_at, expires_at, ended_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            rusqlite::params![
                login.session_hash,
                login.csrf_hash,
                account_id,
                login.created_at,
                login.expires_at,
            ],
        )?;
        insert_audit_event(
            &transaction,
            &NewAuditEvent {
                action: "login",
                actor: login.username,
                target: login.username,
                outcome: "success",
                correlation_id: login.correlation_id,
                created_at: login.created_at,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without Web login"
    )]
    pub(crate) fn web_session(
        &self,
        session_hash: &[u8; 32],
        csrf_hash: Option<&[u8; 32]>,
        now: i64,
    ) -> Result<WebSessionRecord, StoreError> {
        self.connection
            .query_row(
                "SELECT account.username, account.is_administrator, web_session.expires_at
                 FROM web_session
                 JOIN account ON account.id = web_session.account_id
                 WHERE web_session.session_hash = ?1 AND web_session.ended_at IS NULL
                   AND web_session.expires_at >= ?3 AND account.state = 'active'
                   AND (?2 IS NULL OR web_session.csrf_hash = ?2)",
                rusqlite::params![session_hash, csrf_hash, now],
                |row| {
                    Ok(WebSessionRecord {
                        username: row.get(0)?,
                        is_administrator: row.get(1)?,
                        expires_at: row.get(2)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::InvalidSession)
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without Web login"
    )]
    pub(crate) fn end_account_sessions(
        &mut self,
        username: &str,
        ended_at: i64,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account_id: i64 = transaction
            .query_row(
                "SELECT id FROM account WHERE username = ?1",
                [username],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::AccountNotFound(username.to_owned()))?;
        end_sessions(&transaction, account_id, ended_at)?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn create_repository(
        &mut self,
        repository: &NewRepository<'_>,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owner_id = active_account_id(&transaction, repository.owner)?;
        let result = transaction.execute(
            "INSERT INTO repository
             (id, owner_account_id, slug, visibility, state, object_format, created_at, archived_at)
             VALUES (?1, ?2, ?3, 'public', 'active', ?4, ?5, NULL)",
            rusqlite::params![
                repository.id,
                owner_id,
                repository.slug,
                repository.object_format,
                repository.created_at,
            ],
        );
        match result {
            Ok(1) => {
                let event = event::repository(
                    repository.origin.event_kind(),
                    repository.owner,
                    repository.slug,
                    repository.object_format,
                );
                insert_domain_event(
                    &transaction,
                    &NewDomainEvent {
                        repository_id: repository.id,
                        source_intent_id: None,
                        source_ordinal: None,
                        issue_id: None,
                        pull_request_id: None,
                        event: &event,
                        actor: repository.owner,
                        ref_name: None,
                        old_target: None,
                        new_target: None,
                        created_at: repository.created_at,
                    },
                )?;
                for reference in repository.initial_references {
                    let kind = if reference.name.starts_with(b"refs/tags/") {
                        event::EventKind::TagCreated
                    } else if reference.name.starts_with(b"refs/heads/") {
                        event::EventKind::RefCreated
                    } else {
                        return Err(StoreError::EventPayload);
                    };
                    let event =
                        event::reference(kind, &reference.name, None, Some(&reference.target));
                    insert_domain_event(
                        &transaction,
                        &NewDomainEvent {
                            repository_id: repository.id,
                            source_intent_id: None,
                            source_ordinal: None,
                            issue_id: None,
                            pull_request_id: None,
                            event: &event,
                            actor: repository.owner,
                            ref_name: Some(&reference.name),
                            old_target: None,
                            new_target: Some(&reference.target),
                            created_at: repository.created_at,
                        },
                    )?;
                }
                let target = format!("{}/{}", repository.owner, repository.slug);
                insert_audit_event(
                    &transaction,
                    &NewAuditEvent {
                        action: repository.origin.audit_action(),
                        actor: repository.actor,
                        target: &target,
                        outcome: "success",
                        correlation_id: repository.correlation_id,
                        created_at: repository.created_at,
                    },
                )?;
                transaction.commit()?;
            }
            Ok(_) => unreachable!("an INSERT changes one row"),
            Err(error) if is_unique_constraint(&error) => {
                let duplicate_id: bool = transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM repository WHERE id = ?1)",
                    [repository.id],
                    |row| row.get(0),
                )?;
                return if duplicate_id {
                    Err(StoreError::RepositoryIdentifierCollision)
                } else {
                    Err(StoreError::RepositoryExists(
                        repository.owner.to_owned(),
                        repository.slug.to_owned(),
                    ))
                };
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub(crate) fn rename_repository(
        &mut self,
        owner: &str,
        old_slug: &str,
        new_slug: &str,
        changed_at: i64,
        actor: &str,
        correlation_id: &str,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owner_id = active_account_id(&transaction, owner)?;
        let result = transaction.execute(
            "UPDATE repository SET slug = ?3
             WHERE owner_account_id = ?1 AND slug = ?2 AND state = 'active'",
            rusqlite::params![owner_id, old_slug, new_slug],
        );
        match result {
            Ok(1) => {
                let target = format!("{owner}/{old_slug}->{new_slug}");
                insert_audit_event(
                    &transaction,
                    &NewAuditEvent {
                        action: "repository.rename",
                        actor,
                        target: &target,
                        outcome: "success",
                        correlation_id,
                        created_at: changed_at,
                    },
                )?;
                transaction.commit()?;
            }
            Ok(0) => {
                return Err(repository_state_error(
                    &transaction,
                    owner_id,
                    owner,
                    old_slug,
                )?);
            }
            Ok(_) => unreachable!("an owner and slug identify one repository"),
            Err(error) if is_unique_constraint(&error) => {
                return Err(StoreError::RepositoryExists(
                    owner.to_owned(),
                    new_slug.to_owned(),
                ));
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub(crate) fn archive_repository(
        &mut self,
        owner: &str,
        slug: &str,
        archived_at: i64,
        actor: &str,
        correlation_id: &str,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owner_id = active_account_id(&transaction, owner)?;
        let changed = transaction.execute(
            "UPDATE repository SET state = 'archived', archived_at = ?3
             WHERE owner_account_id = ?1 AND slug = ?2 AND state = 'active'",
            rusqlite::params![owner_id, slug, archived_at],
        )?;
        if changed == 0 {
            return Err(repository_state_error(&transaction, owner_id, owner, slug)?);
        }
        let target = format!("{owner}/{slug}");
        insert_audit_event(
            &transaction,
            &NewAuditEvent {
                action: "repository.archive",
                actor,
                target: &target,
                outcome: "success",
                correlation_id,
                created_at: archived_at,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without admin commands"
    )]
    pub(crate) fn set_repository_visibility(
        &mut self,
        owner: &str,
        slug: &str,
        visibility: &str,
        changed_at: i64,
        actor: &str,
        correlation_id: &str,
    ) -> Result<(), StoreError> {
        if !matches!(visibility, "public" | "private") {
            return Err(StoreError::InvalidRepositoryVisibility);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owner_id = active_account_id(&transaction, owner)?;
        let changed = transaction.execute(
            "UPDATE repository SET visibility = ?3
             WHERE owner_account_id = ?1 AND slug = ?2 AND state = 'active'",
            rusqlite::params![owner_id, slug, visibility],
        )?;
        if changed == 0 {
            return Err(repository_state_error(&transaction, owner_id, owner, slug)?);
        }
        let target = format!("{owner}/{slug}:{visibility}");
        insert_audit_event(
            &transaction,
            &NewAuditEvent {
                action: "repository.visibility",
                actor,
                target: &target,
                outcome: "success",
                correlation_id,
                created_at: changed_at,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without admin commands"
    )]
    pub(crate) fn set_repository_collaborator(
        &mut self,
        owner: &str,
        slug: &str,
        username: &str,
        role: &str,
        audit: &AuditContext<'_>,
    ) -> Result<(), StoreError> {
        if !matches!(role, "maintainer" | "writer" | "reader") {
            return Err(StoreError::InvalidCollaboratorRole);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owner_id = active_account_id(&transaction, owner)?;
        let repository_id: Option<String> = transaction
            .query_row(
                "SELECT id FROM repository
                 WHERE owner_account_id = ?1 AND slug = ?2 AND state = 'active'",
                rusqlite::params![owner_id, slug],
                |row| row.get(0),
            )
            .optional()?;
        let Some(repository_id) = repository_id else {
            return Err(repository_state_error(&transaction, owner_id, owner, slug)?);
        };
        let collaborator_id = match active_account_id(&transaction, username) {
            Ok(account_id) => account_id,
            Err(StoreError::AccountNotFound(_)) => {
                return Err(StoreError::CollaboratorNotFound(username.to_owned()));
            }
            Err(error) => return Err(error),
        };
        if collaborator_id == owner_id {
            return Err(StoreError::OwnerCollaborator);
        }
        transaction.execute(
            "INSERT INTO repository_collaborator
             (repository_id, account_id, role, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (repository_id, account_id)
             DO UPDATE SET role = excluded.role",
            rusqlite::params![repository_id, collaborator_id, role, audit.created_at],
        )?;
        let target = format!("{owner}/{slug}:{username}:{role}");
        insert_audit_event(
            &transaction,
            &NewAuditEvent {
                action: "collaborator.set",
                actor: audit.actor,
                target: &target,
                outcome: "success",
                correlation_id: audit.correlation_id,
                created_at: audit.created_at,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without admin commands"
    )]
    pub(crate) fn remove_repository_collaborator(
        &mut self,
        owner: &str,
        slug: &str,
        username: &str,
        changed_at: i64,
        actor: &str,
        correlation_id: &str,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owner_id = active_account_id(&transaction, owner)?;
        let repository_id: Option<String> = transaction
            .query_row(
                "SELECT id FROM repository
                 WHERE owner_account_id = ?1 AND slug = ?2 AND state = 'active'",
                rusqlite::params![owner_id, slug],
                |row| row.get(0),
            )
            .optional()?;
        let Some(repository_id) = repository_id else {
            return Err(repository_state_error(&transaction, owner_id, owner, slug)?);
        };
        let collaborator_id: Option<i64> = transaction
            .query_row(
                "SELECT id FROM account WHERE username = ?1",
                [username],
                |row| row.get(0),
            )
            .optional()?;
        let Some(collaborator_id) = collaborator_id else {
            return Err(StoreError::CollaboratorNotFound(username.to_owned()));
        };
        if collaborator_id == owner_id {
            return Err(StoreError::OwnerCollaborator);
        }
        let changed = transaction.execute(
            "DELETE FROM repository_collaborator
             WHERE repository_id = ?1 AND account_id = ?2",
            rusqlite::params![repository_id, collaborator_id],
        )?;
        if changed == 0 {
            return Err(StoreError::CollaboratorNotFound(username.to_owned()));
        }
        let target = format!("{owner}/{slug}:{username}");
        insert_audit_event(
            &transaction,
            &NewAuditEvent {
                action: "collaborator.remove",
                actor,
                target: &target,
                outcome: "success",
                correlation_id,
                created_at: changed_at,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn repository(
        &self,
        owner: &str,
        slug: &str,
    ) -> Result<RepositoryRecord, StoreError> {
        let result = self.connection.query_row(
            "SELECT repository.id, account.username, repository.slug,
                    repository.visibility, repository.state, repository.object_format,
                    repository.created_at, repository.archived_at
             FROM repository
             JOIN account ON account.id = repository.owner_account_id
             WHERE account.username = ?1 AND repository.slug = ?2",
            rusqlite::params![owner, slug],
            repository_from_row,
        );
        match result {
            Ok(repository) => Ok(repository),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(StoreError::RepositoryNotFound(
                owner.to_owned(),
                slug.to_owned(),
            )),
            Err(error) => Err(error.into()),
        }
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without authorization"
    )]
    pub(crate) fn repository_authorization(
        &self,
        owner: &str,
        slug: &str,
        username: Option<&str>,
    ) -> Result<RepositoryAuthorizationRecord, StoreError> {
        let result = self.connection.query_row(
            "SELECT repository.id, owner.username, repository.slug,
                    repository.visibility, repository.state, repository.object_format,
                    repository.created_at, repository.archived_at,
                    CASE
                        WHEN actor.state != 'active' THEN NULL
                        WHEN actor.id = repository.owner_account_id THEN 'owner'
                        ELSE repository_collaborator.role
                    END
             FROM repository
             JOIN account AS owner ON owner.id = repository.owner_account_id
             LEFT JOIN account AS actor ON actor.username = ?3
             LEFT JOIN repository_collaborator
               ON repository_collaborator.repository_id = repository.id
              AND repository_collaborator.account_id = actor.id
             WHERE owner.username = ?1 AND repository.slug = ?2",
            rusqlite::params![owner, slug, username],
            |row| {
                Ok(RepositoryAuthorizationRecord {
                    repository: repository_from_row(row)?,
                    role: row.get(8)?,
                })
            },
        );
        match result {
            Ok(record) => Ok(record),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(StoreError::RepositoryNotFound(
                owner.to_owned(),
                slug.to_owned(),
            )),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn create_issue(&mut self, issue: &NewIssue<'_>) -> Result<IssueRecord, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let access = repository_issue_access(
            &transaction,
            issue.owner,
            issue.repository,
            Some(issue.actor),
        )?;
        if !access.can_read() {
            return Err(StoreError::IssueHidden);
        }
        let actor_id = access.active_actor_id.ok_or(StoreError::IssueDenied)?;
        transaction.execute(
            "INSERT INTO repository_counter (repository_id)
             VALUES (?1) ON CONFLICT (repository_id) DO NOTHING",
            [&access.repository.id],
        )?;
        let number = transaction.query_row(
            "UPDATE repository_counter
             SET next_issue_number = next_issue_number + 1
             WHERE repository_id = ?1
             RETURNING next_issue_number - 1",
            [&access.repository.id],
            |row| row.get(0),
        )?;
        let id: String =
            transaction.query_row("SELECT lower(hex(randomblob(16)))", [], |row| row.get(0))?;
        transaction.execute(
            "INSERT INTO issue
             (id, repository_id, number, title, body, state, author_account_id,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6, ?7, ?7)",
            rusqlite::params![
                id,
                access.repository.id,
                number,
                issue.title,
                issue.body,
                actor_id,
                issue.created_at,
            ],
        )?;
        let event = event::issue(
            event::EventKind::IssueCreated,
            &id,
            number,
            issue.title,
            issue.body,
        );
        insert_domain_event(
            &transaction,
            &NewDomainEvent {
                repository_id: &access.repository.id,
                source_intent_id: None,
                source_ordinal: None,
                issue_id: Some(&id),
                pull_request_id: None,
                event: &event,
                actor: issue.actor,
                ref_name: None,
                old_target: None,
                new_target: None,
                created_at: issue.created_at,
            },
        )?;
        transaction.commit()?;
        Ok(IssueRecord {
            id,
            number,
            title: issue.title.to_owned(),
            body: issue.body.to_owned(),
            state: "open".to_owned(),
            author: issue.actor.to_owned(),
            created_at: issue.created_at,
            updated_at: issue.created_at,
            closed_at: None,
        })
    }

    pub(crate) fn begin_pull_request_open(
        &mut self,
        intent: &NewPullRequestRefIntent<'_>,
    ) -> Result<PullRequestRefIntentRecord, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let access = repository_issue_access(
            &transaction,
            intent.owner,
            intent.repository,
            Some(intent.actor),
        )?;
        if !access.can_read() {
            return Err(StoreError::PullRequestHidden);
        }
        if !access.can_write_repository() {
            return Err(StoreError::PullRequestDenied);
        }
        let actor_id = access
            .active_actor_id
            .ok_or(StoreError::PullRequestDenied)?;
        transaction.execute(
            "INSERT INTO repository_counter (repository_id)
             VALUES (?1) ON CONFLICT (repository_id) DO NOTHING",
            [&access.repository.id],
        )?;
        let number = transaction.query_row(
            "UPDATE repository_counter
             SET next_pull_request_number = next_pull_request_number + 1
             WHERE repository_id = ?1
             RETURNING next_pull_request_number - 1",
            [&access.repository.id],
            |row| row.get(0),
        )?;
        insert_pull_request_intent(
            &transaction,
            intent,
            &access.repository.id,
            actor_id,
            number,
            1,
            None,
            "open",
        )?;
        transaction.commit()?;
        Ok(PullRequestRefIntentRecord::from_new(
            intent,
            access.repository.id,
            actor_id,
            number,
            1,
            None,
            "open",
        ))
    }

    pub(crate) fn begin_pull_request_revision(
        &mut self,
        number: i64,
        intent: &NewPullRequestRefIntent<'_>,
    ) -> Result<PullRequestRefIntentRecord, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let access = repository_issue_access(
            &transaction,
            intent.owner,
            intent.repository,
            Some(intent.actor),
        )?;
        if !access.can_read() {
            return Err(StoreError::PullRequestHidden);
        }
        if !access.can_write_repository() {
            return Err(StoreError::PullRequestDenied);
        }
        let actor_id = access
            .active_actor_id
            .ok_or(StoreError::PullRequestDenied)?;
        let stored = transaction
            .query_row(
                "SELECT id, title, body, state, base_ref, head_ref, head_object_id,
                        (SELECT COALESCE(MAX(number), 0) + 1
                         FROM pull_request_revision
                         WHERE pull_request_id = pull_request.id)
                 FROM pull_request
                 WHERE repository_id = ?1 AND number = ?2",
                rusqlite::params![access.repository.id, number],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::PullRequestNotFound(
                    intent.owner.to_owned(),
                    intent.repository.to_owned(),
                    number,
                )
            })?;
        let (pull_request_id, title, body, state, base_ref, head_ref, old_head, revision) = stored;
        if state != "open" {
            return Err(StoreError::PullRequestState);
        }
        if pull_request_id != intent.pull_request_id
            || title != intent.title
            || body != intent.body
            || base_ref != intent.base_ref
            || head_ref != intent.head_ref
        {
            return Err(StoreError::PullRequestIntentState(intent.id.to_owned()));
        }
        insert_pull_request_intent(
            &transaction,
            intent,
            &access.repository.id,
            actor_id,
            number,
            revision,
            Some(&old_head),
            "revise",
        )?;
        transaction.commit()?;
        Ok(PullRequestRefIntentRecord::from_new(
            intent,
            access.repository.id,
            actor_id,
            number,
            revision,
            Some(old_head),
            "revise",
        ))
    }

    pub(crate) fn complete_pull_request_ref_intent(&mut self, id: &str) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let intent = pull_request_intent(&transaction, id)?;
        if intent.state != "pending" {
            return Err(StoreError::PullRequestIntentState(id.to_owned()));
        }
        if intent.operation == "open" {
            transaction.execute(
                "INSERT INTO pull_request
                 (id, repository_id, number, title, body, state, author_account_id,
                  base_ref, head_ref, base_object_id, head_object_id, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
                rusqlite::params![
                    intent.pull_request_id,
                    intent.repository_id,
                    intent.pull_request_number,
                    intent.title,
                    intent.body,
                    intent.author_account_id,
                    intent.base_ref,
                    intent.head_ref,
                    intent.base_object_id,
                    intent.head_object_id,
                    intent.created_at,
                ],
            )?;
        } else {
            let changed = transaction.execute(
                "UPDATE pull_request
                 SET base_object_id = ?2, head_object_id = ?3, updated_at = ?4
                 WHERE id = ?1 AND state = 'open' AND head_object_id = ?5",
                rusqlite::params![
                    intent.pull_request_id,
                    intent.base_object_id,
                    intent.head_object_id,
                    intent.created_at,
                    intent.old_head_object_id,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::PullRequestIntentState(id.to_owned()));
            }
        }
        let revision_id: String =
            transaction.query_row("SELECT lower(hex(randomblob(16)))", [], |row| row.get(0))?;
        transaction.execute(
            "INSERT INTO pull_request_revision
             (id, pull_request_id, number, author_account_id, base_object_id,
              head_object_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                revision_id,
                intent.pull_request_id,
                intent.revision_number,
                intent.author_account_id,
                intent.base_object_id,
                intent.head_object_id,
                intent.created_at,
            ],
        )?;
        let kind = if intent.operation == "open" {
            event::EventKind::PullRequestCreated
        } else {
            event::EventKind::PullRequestRevised
        };
        let event = event::pull_request(
            kind,
            &intent.pull_request_id,
            intent.pull_request_number,
            intent.revision_number,
            &intent.title,
            &intent.base_ref,
            &intent.head_ref,
            &intent.base_object_id,
            &intent.head_object_id,
        );
        insert_domain_event(
            &transaction,
            &NewDomainEvent {
                repository_id: &intent.repository_id,
                source_intent_id: None,
                source_ordinal: None,
                issue_id: None,
                pull_request_id: Some(&intent.pull_request_id),
                event: &event,
                actor: &intent.actor,
                ref_name: None,
                old_target: None,
                new_target: None,
                created_at: intent.created_at,
            },
        )?;
        transaction.execute(
            "UPDATE pull_request_ref_intent SET state = 'completed'
             WHERE id = ?1 AND state = 'pending'",
            [id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn abandon_pull_request_ref_intent(&self, id: &str) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE pull_request_ref_intent SET state = 'abandoned'
             WHERE id = ?1 AND state = 'pending'",
            [id],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError::PullRequestIntentState(id.to_owned()))
        }
    }

    pub(crate) fn incomplete_pull_request_ref_intents(
        &self,
    ) -> Result<Vec<PullRequestRefIntentRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, repository_id, pull_request_id, pull_request_number,
                    revision_number, operation, title, body, author_account_id, actor,
                    base_ref, head_ref, base_object_id, old_head_object_id,
                    head_object_id, state, created_at
             FROM pull_request_ref_intent WHERE state = 'pending'
             ORDER BY created_at, id",
        )?;
        statement
            .query_map([], pull_request_intent_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn pull_request(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: Option<&str>,
    ) -> Result<PullRequestDetail, StoreError> {
        let access = repository_issue_access(&self.connection, owner, repository, actor)?;
        if !access.can_read() {
            return Err(StoreError::PullRequestHidden);
        }
        let pull_request = self
            .connection
            .query_row(
                "SELECT pull_request.id, pull_request.number, pull_request.title,
                        pull_request.body, pull_request.state, author.username,
                        pull_request.base_ref, pull_request.head_ref,
                        pull_request.base_object_id, pull_request.head_object_id,
                        pull_request.created_at, pull_request.updated_at
                 FROM pull_request
                 JOIN account AS author ON author.id = pull_request.author_account_id
                 WHERE pull_request.repository_id = ?1 AND pull_request.number = ?2",
                rusqlite::params![access.repository.id, number],
                pull_request_from_row,
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::PullRequestNotFound(owner.to_owned(), repository.to_owned(), number)
            })?;
        let mut statement = self.connection.prepare(
            "SELECT pull_request_revision.id, pull_request_revision.number,
                    author.username, pull_request_revision.base_object_id,
                    pull_request_revision.head_object_id, pull_request_revision.created_at
             FROM pull_request_revision
             JOIN account AS author ON author.id = pull_request_revision.author_account_id
             WHERE pull_request_revision.pull_request_id = ?1
             ORDER BY pull_request_revision.number",
        )?;
        let revisions = statement
            .query_map([&pull_request.id], |row| {
                Ok(PullRequestRevisionRecord {
                    id: row.get(0)?,
                    number: row.get(1)?,
                    author: row.get(2)?,
                    base_object_id: row.get(3)?,
                    head_object_id: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let can_revise = access.can_write_repository();
        Ok(PullRequestDetail {
            repository: access.repository,
            pull_request,
            revisions,
            can_revise,
        })
    }

    pub(crate) fn pull_requests(
        &self,
        owner: &str,
        repository: &str,
        actor: Option<&str>,
    ) -> Result<(RepositoryRecord, Vec<PullRequestRecord>, bool), StoreError> {
        let access = repository_issue_access(&self.connection, owner, repository, actor)?;
        if !access.can_read() {
            return Err(StoreError::PullRequestHidden);
        }
        let mut statement = self.connection.prepare(
            "SELECT pull_request.id, pull_request.number, pull_request.title,
                    pull_request.body, pull_request.state, author.username,
                    pull_request.base_ref, pull_request.head_ref,
                    pull_request.base_object_id, pull_request.head_object_id,
                    pull_request.created_at, pull_request.updated_at
             FROM pull_request
             JOIN account AS author ON author.id = pull_request.author_account_id
             WHERE pull_request.repository_id = ?1
             ORDER BY pull_request.number DESC",
        )?;
        let pull_requests = statement
            .query_map([&access.repository.id], pull_request_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        let can_create = access.can_write_repository();
        Ok((access.repository, pull_requests, can_create))
    }

    pub(crate) fn edit_issue(
        &mut self,
        change: &IssueChange<'_>,
        title: &str,
        body: &str,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (access, current) = issue_mutation_context(
            &transaction,
            change.owner,
            change.repository,
            change.number,
            change.actor,
        )?;
        if !access.can_write_issue(current.author_account_id) {
            return Err(StoreError::IssueDenied);
        }
        transaction.execute(
            "UPDATE issue SET title = ?2, body = ?3, updated_at = ?4 WHERE id = ?1",
            rusqlite::params![current.issue.id, title, body, change.changed_at],
        )?;
        let event = event::issue(
            event::EventKind::IssueEdited,
            &current.issue.id,
            change.number,
            title,
            body,
        );
        insert_issue_event(
            &transaction,
            &access.repository.id,
            &current.issue.id,
            change.actor,
            change.changed_at,
            &event,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn comment_issue(
        &mut self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        body: &str,
        created_at: i64,
    ) -> Result<String, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (access, current) =
            issue_mutation_context(&transaction, owner, repository, number, actor)?;
        let actor_id = access.active_actor_id.ok_or(StoreError::IssueDenied)?;
        if !access.can_read() {
            return Err(StoreError::IssueDenied);
        }
        let comment_id: String =
            transaction.query_row("SELECT lower(hex(randomblob(16)))", [], |row| row.get(0))?;
        transaction.execute(
            "INSERT INTO issue_comment
             (id, issue_id, author_account_id, body, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![comment_id, current.issue.id, actor_id, body, created_at],
        )?;
        transaction.execute(
            "UPDATE issue SET updated_at = ?2 WHERE id = ?1",
            rusqlite::params![current.issue.id, created_at],
        )?;
        let event = event::issue_comment(&current.issue.id, number, &comment_id, actor, body);
        insert_issue_event(
            &transaction,
            &access.repository.id,
            &current.issue.id,
            actor,
            created_at,
            &event,
        )?;
        transaction.commit()?;
        Ok(comment_id)
    }

    pub(crate) fn set_issue_state(
        &mut self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        state: &str,
        changed_at: i64,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (access, current) =
            issue_mutation_context(&transaction, owner, repository, number, actor)?;
        if !access.can_write_issue(current.author_account_id) {
            return Err(StoreError::IssueDenied);
        }
        if current.issue.state == state {
            return Err(StoreError::IssueState(state.to_owned()));
        }
        let (closed_at, kind) = match state {
            "closed" => (Some(changed_at), event::EventKind::IssueClosed),
            "open" => (None, event::EventKind::IssueReopened),
            _ => return Err(StoreError::IssueState(state.to_owned())),
        };
        transaction.execute(
            "UPDATE issue
             SET state = ?2, updated_at = ?3, closed_at = ?4
             WHERE id = ?1",
            rusqlite::params![current.issue.id, state, changed_at, closed_at],
        )?;
        let event = event::issue_state(kind, &current.issue.id, number, state);
        insert_issue_event(
            &transaction,
            &access.repository.id,
            &current.issue.id,
            actor,
            changed_at,
            &event,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn set_issue_label(
        &mut self,
        change: &IssueChange<'_>,
        label: &str,
        present: bool,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (access, current) = issue_mutation_context(
            &transaction,
            change.owner,
            change.repository,
            change.number,
            change.actor,
        )?;
        let actor_id = access.active_actor_id.ok_or(StoreError::IssueDenied)?;
        if !access.can_maintain() {
            return Err(StoreError::IssueDenied);
        }
        let (label_id, stored_label) = if present {
            transaction.execute(
                "INSERT INTO label (id, repository_id, name, created_at)
                 VALUES (lower(hex(randomblob(16))), ?1, ?2, ?3)
                 ON CONFLICT DO NOTHING",
                rusqlite::params![access.repository.id, label, change.changed_at],
            )?;
            transaction.query_row(
                "SELECT id, name FROM label
                 WHERE repository_id = ?1 AND name = ?2 COLLATE NOCASE",
                rusqlite::params![access.repository.id, label],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
        } else {
            transaction
                .query_row(
                    "SELECT id, name FROM label
                     WHERE repository_id = ?1 AND name = ?2 COLLATE NOCASE",
                    rusqlite::params![access.repository.id, label],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .ok_or(StoreError::IssueLabelState)?
        };
        let changed = if present {
            transaction.execute(
                "INSERT INTO issue_label (issue_id, label_id, actor_account_id, created_at)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                rusqlite::params![current.issue.id, label_id, actor_id, change.changed_at],
            )?
        } else {
            transaction.execute(
                "DELETE FROM issue_label WHERE issue_id = ?1 AND label_id = ?2",
                rusqlite::params![current.issue.id, label_id],
            )?
        };
        if changed == 0 {
            return Err(StoreError::IssueLabelState);
        }
        transaction.execute(
            "UPDATE issue SET updated_at = ?2 WHERE id = ?1",
            rusqlite::params![current.issue.id, change.changed_at],
        )?;
        let kind = if present {
            event::EventKind::IssueLabeled
        } else {
            event::EventKind::IssueUnlabeled
        };
        let event = event::issue_label(
            kind,
            &current.issue.id,
            change.number,
            &label_id,
            &stored_label,
        );
        insert_issue_event(
            &transaction,
            &access.repository.id,
            &current.issue.id,
            change.actor,
            change.changed_at,
            &event,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn set_issue_assignee(
        &mut self,
        change: &IssueChange<'_>,
        assignee: &str,
        present: bool,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (access, current) = issue_mutation_context(
            &transaction,
            change.owner,
            change.repository,
            change.number,
            change.actor,
        )?;
        let actor_id = access.active_actor_id.ok_or(StoreError::IssueDenied)?;
        if !access.can_maintain() {
            return Err(StoreError::IssueDenied);
        }
        let assignee_access = repository_issue_access(
            &transaction,
            change.owner,
            change.repository,
            Some(assignee),
        )?;
        let assignee_id = assignee_access
            .active_actor_id
            .filter(|_| assignee_access.can_read())
            .ok_or_else(|| StoreError::IssueAssigneeNotFound(assignee.to_owned()))?;
        let changed = if present {
            transaction.execute(
                "INSERT INTO issue_assignee
                 (issue_id, account_id, actor_account_id, created_at)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                rusqlite::params![current.issue.id, assignee_id, actor_id, change.changed_at],
            )?
        } else {
            transaction.execute(
                "DELETE FROM issue_assignee WHERE issue_id = ?1 AND account_id = ?2",
                rusqlite::params![current.issue.id, assignee_id],
            )?
        };
        if changed == 0 {
            return Err(StoreError::IssueAssigneeState);
        }
        transaction.execute(
            "UPDATE issue SET updated_at = ?2 WHERE id = ?1",
            rusqlite::params![current.issue.id, change.changed_at],
        )?;
        let kind = if present {
            event::EventKind::IssueAssigned
        } else {
            event::EventKind::IssueUnassigned
        };
        let event = event::issue_assignee(kind, &current.issue.id, change.number, assignee);
        insert_issue_event(
            &transaction,
            &access.repository.id,
            &current.issue.id,
            change.actor,
            change.changed_at,
            &event,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn issues(
        &self,
        owner: &str,
        repository: &str,
        actor: Option<&str>,
    ) -> Result<(RepositoryRecord, Vec<IssueRecord>), StoreError> {
        let access = repository_issue_access(&self.connection, owner, repository, actor)?;
        if !access.can_read() {
            return Err(StoreError::IssueHidden);
        }
        let mut statement = self.connection.prepare(
            "SELECT issue.id, issue.number, issue.title, issue.body, issue.state,
                    account.username, issue.created_at, issue.updated_at, issue.closed_at
             FROM issue
             JOIN account ON account.id = issue.author_account_id
             WHERE issue.repository_id = ?1
             ORDER BY issue.number DESC LIMIT 1000",
        )?;
        let issues = statement
            .query_map([&access.repository.id], issue_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        Ok((access.repository, issues))
    }

    pub(crate) fn issue_detail(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: Option<&str>,
    ) -> Result<IssueDetail, StoreError> {
        let access = repository_issue_access(&self.connection, owner, repository, actor)?;
        if !access.can_read() {
            return Err(StoreError::IssueHidden);
        }
        let issue = find_issue(
            &self.connection,
            &access.repository,
            owner,
            repository,
            number,
        )?;
        let comments = {
            let mut statement = self.connection.prepare(
                "SELECT issue_comment.id, account.username, issue_comment.body,
                        issue_comment.created_at
                 FROM issue_comment
                 JOIN account ON account.id = issue_comment.author_account_id
                 WHERE issue_comment.issue_id = ?1
                 ORDER BY issue_comment.created_at, issue_comment.id",
            )?;
            statement
                .query_map([&issue.issue.id], |row| {
                    Ok(IssueCommentRecord {
                        id: row.get(0)?,
                        author: row.get(1)?,
                        body: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let labels = issue_names(
            &self.connection,
            "SELECT label.name FROM issue_label
             JOIN label ON label.id = issue_label.label_id
             WHERE issue_label.issue_id = ?1 ORDER BY label.name COLLATE NOCASE",
            &issue.issue.id,
        )?;
        let assignees = issue_names(
            &self.connection,
            "SELECT account.username FROM issue_assignee
             JOIN account ON account.id = issue_assignee.account_id
             WHERE issue_assignee.issue_id = ?1 ORDER BY account.username",
            &issue.issue.id,
        )?;
        let timeline = {
            let mut statement = self.connection.prepare(
                "SELECT sequence, kind, actor, payload, created_at
                 FROM repository_event WHERE issue_id = ?1 ORDER BY sequence",
            )?;
            statement
                .query_map([&issue.issue.id], |row| {
                    Ok(IssueTimelineRecord {
                        sequence: row.get(0)?,
                        kind: row.get(1)?,
                        actor: row.get(2)?,
                        payload: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        Ok(IssueDetail {
            can_comment: access.active_actor_id.is_some() && access.can_read(),
            can_edit: access.can_write_issue(issue.author_account_id),
            can_maintain: access.can_maintain(),
            repository: access.repository,
            issue: issue.issue,
            comments,
            labels,
            assignees,
            timeline,
        })
    }

    pub(crate) fn watch(
        &self,
        owner: &str,
        repository: &str,
        actor: Option<&str>,
    ) -> Result<(RepositoryRecord, Option<WatchRecord>), StoreError> {
        let access = repository_issue_access(&self.connection, owner, repository, actor)?;
        if !access.can_read() {
            return Err(StoreError::WatchDenied);
        }
        let watch = match access.active_actor_id {
            Some(actor_id) => self
                .connection
                .query_row(
                    "SELECT id, pushes, issues, pull_requests, created_at, updated_at
                 FROM watch WHERE repository_id = ?1 AND account_id = ?2",
                    rusqlite::params![access.repository.id, actor_id],
                    |row| {
                        Ok(WatchRecord {
                            id: row.get(0)?,
                            pushes: row.get(1)?,
                            issues: row.get(2)?,
                            pull_requests: row.get(3)?,
                            created_at: row.get(4)?,
                            updated_at: row.get(5)?,
                        })
                    },
                )
                .optional()?,
            None => None,
        };
        Ok((access.repository, watch))
    }

    pub(crate) fn set_watch(
        &mut self,
        owner: &str,
        repository: &str,
        actor: &str,
        preferences: WatchPreferences,
        changed_at: i64,
    ) -> Result<Option<WatchRecord>, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let access = repository_issue_access(&transaction, owner, repository, Some(actor))?;
        let actor_id = access.active_actor_id.ok_or(StoreError::WatchDenied)?;
        if !access.can_read() {
            return Err(StoreError::WatchDenied);
        }
        if !preferences.any() {
            transaction.execute(
                "DELETE FROM watch WHERE repository_id = ?1 AND account_id = ?2",
                rusqlite::params![access.repository.id, actor_id],
            )?;
            transaction.commit()?;
            return Ok(None);
        }
        transaction.execute(
            "INSERT INTO watch
             (id, repository_id, account_id, pushes, issues, pull_requests,
              created_at, updated_at)
             VALUES (lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT (repository_id, account_id) DO UPDATE SET
                 pushes = excluded.pushes,
                 issues = excluded.issues,
                 pull_requests = excluded.pull_requests,
                 updated_at = excluded.updated_at",
            rusqlite::params![
                access.repository.id,
                actor_id,
                preferences.pushes,
                preferences.issues,
                preferences.pull_requests,
                changed_at,
            ],
        )?;
        let record = transaction.query_row(
            "SELECT id, pushes, issues, pull_requests, created_at, updated_at
             FROM watch WHERE repository_id = ?1 AND account_id = ?2",
            rusqlite::params![access.repository.id, actor_id],
            |row| {
                Ok(WatchRecord {
                    id: row.get(0)?,
                    pushes: row.get(1)?,
                    issues: row.get(2)?,
                    pull_requests: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        )?;
        transaction.commit()?;
        Ok(Some(record))
    }

    pub(crate) fn create_feed_token(
        &mut self,
        actor: &str,
        scope: &str,
        repository: Option<(&str, &str)>,
        token_hash: &[u8; 32],
        created_at: i64,
    ) -> Result<FeedTokenRecord, StoreError> {
        validate_feed_scope(scope, repository)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account_id = active_account_id(&transaction, actor)?;
        let active_tokens: i64 = transaction.query_row(
            "SELECT count(*) FROM feed_token
             WHERE account_id = ?1 AND revoked_at IS NULL",
            [account_id],
            |row| row.get(0),
        )?;
        if active_tokens >= MAX_ACTIVE_FEED_TOKENS {
            return Err(StoreError::FeedTokenLimit);
        }
        let repository_id = match repository {
            Some((owner, repository)) => {
                let access = repository_issue_access(&transaction, owner, repository, Some(actor))?;
                if !access.can_read() {
                    return Err(StoreError::FeedTokenDenied);
                }
                Some(access.repository.id)
            }
            None => None,
        };
        transaction.execute(
            "INSERT INTO feed_token
             (id, token_hash, account_id, scope, repository_id, created_at, revoked_at)
             VALUES (lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, ?5, NULL)",
            rusqlite::params![
                token_hash.as_slice(),
                account_id,
                scope,
                repository_id,
                created_at
            ],
        )?;
        let record = transaction.query_row(
            "SELECT feed_token.id, feed_token.scope, owner.username, repository.slug,
                    feed_token.created_at, feed_token.revoked_at
             FROM feed_token
             LEFT JOIN repository ON repository.id = feed_token.repository_id
             LEFT JOIN account AS owner ON owner.id = repository.owner_account_id
             WHERE feed_token.rowid = last_insert_rowid()",
            [],
            feed_token_from_row,
        )?;
        transaction.commit()?;
        Ok(record)
    }

    pub(crate) fn feed_tokens(&self, actor: &str) -> Result<Vec<FeedTokenRecord>, StoreError> {
        let account_id = active_account_id(&self.connection, actor)?;
        let mut statement = self.connection.prepare(
            "SELECT feed_token.id, feed_token.scope, owner.username, repository.slug,
                    feed_token.created_at, feed_token.revoked_at
             FROM feed_token
             LEFT JOIN repository ON repository.id = feed_token.repository_id
             LEFT JOIN account AS owner ON owner.id = repository.owner_account_id
             WHERE feed_token.account_id = ?1
             ORDER BY feed_token.created_at DESC, feed_token.id
             LIMIT 100",
        )?;
        statement
            .query_map([account_id], feed_token_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn rotate_feed_token(
        &mut self,
        actor: &str,
        id: &str,
        token_hash: &[u8; 32],
        changed_at: i64,
    ) -> Result<FeedTokenRecord, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let account_id = active_account_id(&transaction, actor)?;
        let current = transaction
            .query_row(
                "SELECT scope, repository_id FROM feed_token
                 WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL",
                rusqlite::params![id, account_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .ok_or(StoreError::FeedTokenNotFound)?;
        transaction.execute(
            "UPDATE feed_token SET revoked_at = ?3
             WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL",
            rusqlite::params![id, account_id, changed_at],
        )?;
        transaction.execute(
            "INSERT INTO feed_token
             (id, token_hash, account_id, scope, repository_id, created_at, revoked_at)
             VALUES (lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, ?5, NULL)",
            rusqlite::params![
                token_hash.as_slice(),
                account_id,
                current.0,
                current.1,
                changed_at
            ],
        )?;
        let record = transaction.query_row(
            "SELECT feed_token.id, feed_token.scope, owner.username, repository.slug,
                    feed_token.created_at, feed_token.revoked_at
             FROM feed_token
             LEFT JOIN repository ON repository.id = feed_token.repository_id
             LEFT JOIN account AS owner ON owner.id = repository.owner_account_id
             WHERE feed_token.rowid = last_insert_rowid()",
            [],
            feed_token_from_row,
        )?;
        transaction.commit()?;
        Ok(record)
    }

    pub(crate) fn revoke_feed_token(
        &mut self,
        actor: &str,
        id: &str,
        revoked_at: i64,
    ) -> Result<(), StoreError> {
        let account_id = active_account_id(&self.connection, actor)?;
        let changed = self.connection.execute(
            "UPDATE feed_token SET revoked_at = ?3
             WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL",
            rusqlite::params![id, account_id, revoked_at],
        )?;
        if changed == 0 {
            return Err(StoreError::FeedTokenNotFound);
        }
        Ok(())
    }

    pub(crate) fn token_feed_events(
        &self,
        token_hash: &[u8; 32],
        limit: usize,
    ) -> Result<TokenFeedPage, StoreError> {
        let limit = i64::try_from(limit).map_err(|_| StoreError::EventLimit)?;
        let grant = self
            .connection
            .query_row(
                "SELECT feed_token.scope, feed_token.repository_id,
                        account.id, account.username
                 FROM feed_token
                 JOIN account ON account.id = feed_token.account_id
                 WHERE feed_token.token_hash = ?1 AND feed_token.revoked_at IS NULL
                   AND account.state = 'active'",
                [token_hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::FeedTokenNotFound)?;
        let events = match grant.0.as_str() {
            "repository" => token_repository_events(
                &self.connection,
                grant.1.as_deref().ok_or(StoreError::InvalidFeedScope)?,
                grant.2,
                limit,
            )?,
            "watched" => watched_feed_events(&self.connection, grant.2, limit)?,
            "assignments" => assignment_feed_events(&self.connection, grant.2, &grant.3, limit)?,
            "mentions" => mention_feed_events(&self.connection, grant.2, &grant.3, limit)?,
            _ => return Err(StoreError::InvalidFeedScope),
        };
        Ok(TokenFeedPage {
            scope: grant.0,
            username: grant.3,
            target: grant.1,
            events,
        })
    }

    pub(crate) fn visit_metadata_search_candidates(
        &self,
        actor: Option<&str>,
        limit: usize,
        max_field_bytes: usize,
        mut visit: impl FnMut(MetadataSearchCandidate) -> bool,
    ) -> Result<bool, StoreError> {
        let query_limit = limit.checked_add(1).ok_or(StoreError::EventLimit)?;
        let query_limit = i64::try_from(query_limit).map_err(|_| StoreError::EventLimit)?;
        let max_field_bytes = max_field_bytes
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(StoreError::EventLimit)?;
        let mut statement = self.connection.prepare(
            "WITH visible_repository AS (
                 SELECT repository.id, owner.username AS owner, repository.slug
                 FROM repository
                 JOIN account AS owner ON owner.id = repository.owner_account_id
                 LEFT JOIN account AS actor
                   ON actor.username = ?1 AND actor.state = 'active'
                 WHERE repository.state = 'active'
                   AND (repository.visibility = 'public'
                        OR repository.owner_account_id = actor.id
                        OR EXISTS (
                            SELECT 1 FROM repository_collaborator
                            WHERE repository_collaborator.repository_id = repository.id
                              AND repository_collaborator.account_id = actor.id
                        ))
             ), candidates AS (
                 SELECT 'repository' AS kind, visible_repository.id AS record_id,
                        visible_repository.owner, visible_repository.slug,
                        NULL AS issue_number,
                        CAST(visible_repository.owner || '/' || visible_repository.slug AS BLOB)
                            AS title,
                        X'' AS body
                 FROM visible_repository
                 UNION ALL
                 SELECT 'issue', issue.id, visible_repository.owner,
                        visible_repository.slug, issue.number,
                        COALESCE(substr(CAST(issue.title AS BLOB), 1, ?3), X''),
                        COALESCE(substr(CAST(issue.body AS BLOB), 1, ?3), X'')
                 FROM issue
                 JOIN visible_repository ON visible_repository.id = issue.repository_id
                 UNION ALL
                 SELECT 'issue-comment', issue_comment.id, visible_repository.owner,
                        visible_repository.slug, issue.number,
                        COALESCE(substr(CAST(issue.title AS BLOB), 1, ?3), X''),
                        COALESCE(substr(CAST(issue_comment.body AS BLOB), 1, ?3), X'')
                 FROM issue_comment
                 JOIN issue ON issue.id = issue_comment.issue_id
                 JOIN visible_repository ON visible_repository.id = issue.repository_id
             )
             SELECT kind, record_id, owner, slug, issue_number, title, body
             FROM candidates
             ORDER BY owner, slug, kind, issue_number, record_id
             LIMIT ?2",
        )?;
        let mut rows = statement.query(rusqlite::params![actor, query_limit, max_field_bytes])?;
        let mut visited = 0_usize;
        while let Some(row) = rows.next()? {
            if visited == limit {
                return Ok(true);
            }
            visited += 1;
            let candidate = MetadataSearchCandidate {
                kind: row.get(0)?,
                record_id: row.get(1)?,
                owner: row.get(2)?,
                repository: row.get(3)?,
                issue_number: row.get(4)?,
                title: row.get(5)?,
                body: row.get(6)?,
            };
            if !visit(candidate) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without authorization"
    )]
    pub(crate) fn active_repositories(&self) -> Result<Vec<RepositoryRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT repository.id, account.username, repository.slug,
                    repository.visibility, repository.state, repository.object_format,
                    repository.created_at, repository.archived_at
             FROM repository
             JOIN account ON account.id = repository.owner_account_id
             WHERE repository.state = 'active'
             ORDER BY account.username, repository.slug",
        )?;
        statement
            .query_map([], repository_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[allow(
        dead_code,
        reason = "some integration tests import the store without public HTTP routes"
    )]
    pub(crate) fn public_repository(
        &self,
        owner: &str,
        slug: &str,
    ) -> Result<RepositoryRecord, StoreError> {
        let result = self.connection.query_row(
            "SELECT repository.id, account.username, repository.slug,
                    repository.visibility, repository.state, repository.object_format,
                    repository.created_at, repository.archived_at
             FROM repository
             JOIN account ON account.id = repository.owner_account_id
             WHERE account.username = ?1 AND repository.slug = ?2
               AND repository.visibility = 'public' AND repository.state = 'active'",
            rusqlite::params![owner, slug],
            repository_from_row,
        );
        match result {
            Ok(repository) => Ok(repository),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(StoreError::RepositoryNotFound(
                owner.to_owned(),
                slug.to_owned(),
            )),
            Err(error) => Err(error.into()),
        }
    }

    #[allow(
        dead_code,
        reason = "some integration tests import storage without the server"
    )]
    pub(crate) fn active_ssh_public_keys(&self) -> Result<Vec<String>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT ssh_public_key.canonical_key
             FROM ssh_public_key
             JOIN account ON account.id = ssh_public_key.account_id
             WHERE account.state = 'active' AND ssh_public_key.revoked_at IS NULL
             ORDER BY ssh_public_key.id",
        )?;
        statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile storage without the production SSH server"
    )]
    pub(crate) fn active_ssh_identities(&self) -> Result<Vec<ActiveSshIdentity>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT account.username, ssh_public_key.canonical_key,
                    ssh_public_key.fingerprint
             FROM ssh_public_key
             JOIN account ON account.id = ssh_public_key.account_id
             WHERE account.state = 'active' AND ssh_public_key.revoked_at IS NULL
             ORDER BY ssh_public_key.id",
        )?;
        statement
            .query_map([], |row| {
                Ok(ActiveSshIdentity {
                    username: row.get(0)?,
                    canonical_key: row.get(1)?,
                    fingerprint: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[allow(
        dead_code,
        reason = "some integration tests import storage without the server"
    )]
    pub(crate) fn active_public_repositories(&self) -> Result<Vec<RepositoryRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT repository.id, account.username, repository.slug,
                    repository.visibility, repository.state, repository.object_format,
                    repository.created_at, repository.archived_at
             FROM repository
             JOIN account ON account.id = repository.owner_account_id
             WHERE repository.visibility = 'public' AND repository.state = 'active'
             ORDER BY account.username, repository.slug",
        )?;
        statement
            .query_map([], repository_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[allow(
        dead_code,
        reason = "some integration tests import storage without public event pages"
    )]
    pub(crate) fn public_repository_events(
        &self,
        owner: &str,
        slug: &str,
        before: Option<i64>,
        limit: usize,
    ) -> Result<(RepositoryRecord, Vec<RepositoryEventRecord>), StoreError> {
        let repository = self.public_repository(owner, slug)?;
        self.repository_events_for(repository, before, limit, false)
    }

    #[allow(
        dead_code,
        reason = "some integration tests use only public event queries"
    )]
    pub(crate) fn repository_events(
        &self,
        owner: &str,
        slug: &str,
        before: Option<i64>,
        limit: usize,
    ) -> Result<(RepositoryRecord, Vec<RepositoryEventRecord>), StoreError> {
        let repository = self.repository(owner, slug)?;
        self.repository_events_for(repository, before, limit, false)
    }

    pub(crate) fn repository_issue_events(
        &self,
        owner: &str,
        slug: &str,
        before: Option<i64>,
        limit: usize,
    ) -> Result<(RepositoryRecord, Vec<RepositoryEventRecord>), StoreError> {
        let repository = self.repository(owner, slug)?;
        self.repository_events_for(repository, before, limit, true)
    }

    fn repository_events_for(
        &self,
        repository: RepositoryRecord,
        before: Option<i64>,
        limit: usize,
        issues_only: bool,
    ) -> Result<(RepositoryRecord, Vec<RepositoryEventRecord>), StoreError> {
        let limit = i64::try_from(limit).map_err(|_| StoreError::EventLimit)?;
        let mut statement = self.connection.prepare(
            "SELECT event_id, sequence, kind, actor, ref_name, old_target, new_target,
                    payload_version, payload, created_at
             FROM repository_event
             WHERE repository_id = ?1 AND (?2 IS NULL OR sequence < ?2)
               AND (?4 = 0 OR kind LIKE 'issue-%')
             ORDER BY sequence DESC
             LIMIT ?3",
        )?;
        let events = statement
            .query_map(
                rusqlite::params![repository.id, before, limit, issues_only],
                |row| {
                    Ok(RepositoryEventRecord {
                        event_id: row.get(0)?,
                        sequence: row.get(1)?,
                        kind: row.get(2)?,
                        actor: row.get(3)?,
                        ref_name: row.get(4)?,
                        old_target: row.get(5)?,
                        new_target: row.get(6)?,
                        payload_version: row.get(7)?,
                        payload: row.get(8)?,
                        created_at: row.get(9)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok((repository, events))
    }
}

pub(crate) struct InitialAdministrator<'a> {
    pub(crate) username: &'a str,
    pub(crate) canonical_key: &'a str,
    pub(crate) fingerprint: &'a str,
    pub(crate) recovery_hash: &'a [u8; 32],
    pub(crate) created_at: i64,
}

#[allow(
    dead_code,
    reason = "some integration tests compile storage without accounts"
)]
pub(crate) struct NewSshKey<'a> {
    pub(crate) canonical_key: &'a str,
    pub(crate) fingerprint: &'a str,
    pub(crate) label: &'a str,
}

#[allow(
    dead_code,
    reason = "some integration tests compile storage without accounts"
)]
pub(crate) struct InvitedAccount<'a> {
    pub(crate) invitation_hash: &'a [u8; 32],
    pub(crate) username: &'a str,
    pub(crate) key: NewSshKey<'a>,
    pub(crate) recovery_hash: &'a [u8; 32],
    pub(crate) created_at: i64,
    pub(crate) correlation_id: &'a str,
}

#[allow(
    dead_code,
    reason = "some integration tests compile storage without accounts"
)]
pub(crate) struct AccountRecovery<'a> {
    pub(crate) username: &'a str,
    pub(crate) old_recovery_hash: &'a [u8; 32],
    pub(crate) key: NewSshKey<'a>,
    pub(crate) new_recovery_hash: &'a [u8; 32],
    pub(crate) created_at: i64,
    pub(crate) correlation_id: &'a str,
}

#[allow(
    dead_code,
    reason = "some integration tests compile storage without Web login"
)]
pub(crate) struct NewLoginNonce<'a> {
    pub(crate) nonce_hash: &'a [u8; 32],
    pub(crate) csrf_hash: &'a [u8; 32],
    pub(crate) username: &'a str,
    pub(crate) fingerprint: &'a str,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
}

#[allow(
    dead_code,
    reason = "some integration tests compile storage without Web login"
)]
pub(crate) struct NewWebSession<'a> {
    pub(crate) nonce_hash: &'a [u8; 32],
    pub(crate) login_csrf_hash: &'a [u8; 32],
    pub(crate) username: &'a str,
    pub(crate) fingerprint: &'a str,
    pub(crate) session_hash: &'a [u8; 32],
    pub(crate) csrf_hash: &'a [u8; 32],
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) correlation_id: &'a str,
}

#[allow(
    dead_code,
    reason = "some integration tests compile storage without Web login"
)]
pub(crate) struct WebSessionRecord {
    pub(crate) username: String,
    pub(crate) is_administrator: bool,
    pub(crate) expires_at: i64,
}

pub(crate) struct NewRepository<'a> {
    pub(crate) id: &'a str,
    pub(crate) owner: &'a str,
    pub(crate) slug: &'a str,
    pub(crate) object_format: &'a str,
    pub(crate) created_at: i64,
    pub(crate) origin: RepositoryOrigin,
    pub(crate) initial_references: &'a [NewRepositoryReference],
    pub(crate) actor: &'a str,
    pub(crate) correlation_id: &'a str,
}

#[derive(Clone, Copy)]
#[allow(
    dead_code,
    reason = "some integration tests create repositories without the import operation"
)]
pub(crate) enum RepositoryOrigin {
    Created,
    Imported,
}

impl RepositoryOrigin {
    fn event_kind(self) -> event::EventKind {
        match self {
            Self::Created => event::EventKind::RepositoryCreated,
            Self::Imported => event::EventKind::RepositoryImported,
        }
    }

    fn audit_action(self) -> &'static str {
        match self {
            Self::Created => "repository.create",
            Self::Imported => "repository.import",
        }
    }
}

pub(crate) struct NewRepositoryReference {
    pub(crate) name: Vec<u8>,
    pub(crate) target: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RepositoryRecord {
    pub(crate) id: String,
    pub(crate) owner: String,
    pub(crate) slug: String,
    pub(crate) visibility: String,
    pub(crate) state: String,
    pub(crate) object_format: String,
    pub(crate) created_at: i64,
    pub(crate) archived_at: Option<i64>,
}

#[allow(
    dead_code,
    reason = "some integration tests compile storage without authorization"
)]
pub(crate) struct RepositoryAuthorizationRecord {
    pub(crate) repository: RepositoryRecord,
    pub(crate) role: Option<String>,
}

#[allow(
    dead_code,
    reason = "some integration tests compile storage without the production SSH server"
)]
pub(crate) struct ActiveSshIdentity {
    pub(crate) username: String,
    pub(crate) canonical_key: String,
    pub(crate) fingerprint: String,
}

#[allow(
    dead_code,
    reason = "some integration tests import storage without public event pages"
)]
pub(crate) struct RepositoryEventRecord {
    pub(crate) event_id: String,
    pub(crate) sequence: i64,
    pub(crate) kind: String,
    pub(crate) actor: String,
    pub(crate) ref_name: Option<Vec<u8>>,
    pub(crate) old_target: Option<String>,
    pub(crate) new_target: Option<String>,
    pub(crate) payload_version: i64,
    pub(crate) payload: String,
    pub(crate) created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IssueRecord {
    pub(crate) id: String,
    pub(crate) number: i64,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) state: String,
    pub(crate) author: String,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) closed_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IssueCommentRecord {
    pub(crate) id: String,
    pub(crate) author: String,
    pub(crate) body: String,
    pub(crate) created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IssueTimelineRecord {
    pub(crate) sequence: i64,
    pub(crate) kind: String,
    pub(crate) actor: String,
    pub(crate) payload: String,
    pub(crate) created_at: i64,
}

pub(crate) struct IssueDetail {
    pub(crate) repository: RepositoryRecord,
    pub(crate) issue: IssueRecord,
    pub(crate) comments: Vec<IssueCommentRecord>,
    pub(crate) labels: Vec<String>,
    pub(crate) assignees: Vec<String>,
    pub(crate) timeline: Vec<IssueTimelineRecord>,
    pub(crate) can_comment: bool,
    pub(crate) can_edit: bool,
    pub(crate) can_maintain: bool,
}

pub(crate) struct NewIssue<'a> {
    pub(crate) owner: &'a str,
    pub(crate) repository: &'a str,
    pub(crate) actor: &'a str,
    pub(crate) title: &'a str,
    pub(crate) body: &'a str,
    pub(crate) created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PullRequestRecord {
    pub(crate) id: String,
    pub(crate) number: i64,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) state: String,
    pub(crate) author: String,
    pub(crate) base_ref: String,
    pub(crate) head_ref: String,
    pub(crate) base_object_id: String,
    pub(crate) head_object_id: String,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PullRequestRevisionRecord {
    pub(crate) id: String,
    pub(crate) number: i64,
    pub(crate) author: String,
    pub(crate) base_object_id: String,
    pub(crate) head_object_id: String,
    pub(crate) created_at: i64,
}

pub(crate) struct PullRequestDetail {
    pub(crate) repository: RepositoryRecord,
    pub(crate) pull_request: PullRequestRecord,
    pub(crate) revisions: Vec<PullRequestRevisionRecord>,
    pub(crate) can_revise: bool,
}

pub(crate) struct NewPullRequestRefIntent<'a> {
    pub(crate) id: &'a str,
    pub(crate) pull_request_id: &'a str,
    pub(crate) owner: &'a str,
    pub(crate) repository: &'a str,
    pub(crate) actor: &'a str,
    pub(crate) title: &'a str,
    pub(crate) body: &'a str,
    pub(crate) base_ref: &'a str,
    pub(crate) head_ref: &'a str,
    pub(crate) base_object_id: &'a str,
    pub(crate) head_object_id: &'a str,
    pub(crate) created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PullRequestRefIntentRecord {
    pub(crate) id: String,
    pub(crate) repository_id: String,
    pub(crate) pull_request_id: String,
    pub(crate) pull_request_number: i64,
    pub(crate) revision_number: i64,
    pub(crate) operation: String,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) author_account_id: i64,
    pub(crate) actor: String,
    pub(crate) base_ref: String,
    pub(crate) head_ref: String,
    pub(crate) base_object_id: String,
    pub(crate) old_head_object_id: Option<String>,
    pub(crate) head_object_id: String,
    pub(crate) state: String,
    pub(crate) created_at: i64,
}

impl PullRequestRefIntentRecord {
    #[allow(clippy::too_many_arguments)]
    fn from_new(
        intent: &NewPullRequestRefIntent<'_>,
        repository_id: String,
        author_account_id: i64,
        pull_request_number: i64,
        revision_number: i64,
        old_head_object_id: Option<String>,
        operation: &str,
    ) -> Self {
        Self {
            id: intent.id.to_owned(),
            repository_id,
            pull_request_id: intent.pull_request_id.to_owned(),
            pull_request_number,
            revision_number,
            operation: operation.to_owned(),
            title: intent.title.to_owned(),
            body: intent.body.to_owned(),
            author_account_id,
            actor: intent.actor.to_owned(),
            base_ref: intent.base_ref.to_owned(),
            head_ref: intent.head_ref.to_owned(),
            base_object_id: intent.base_object_id.to_owned(),
            old_head_object_id,
            head_object_id: intent.head_object_id.to_owned(),
            state: "pending".to_owned(),
            created_at: intent.created_at,
        }
    }
}

pub(crate) struct IssueChange<'a> {
    pub(crate) owner: &'a str,
    pub(crate) repository: &'a str,
    pub(crate) number: i64,
    pub(crate) actor: &'a str,
    pub(crate) changed_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WatchPreferences {
    pub(crate) pushes: bool,
    pub(crate) issues: bool,
    pub(crate) pull_requests: bool,
}

impl WatchPreferences {
    pub(crate) fn any(self) -> bool {
        self.pushes || self.issues || self.pull_requests
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WatchRecord {
    pub(crate) id: String,
    pub(crate) pushes: bool,
    pub(crate) issues: bool,
    pub(crate) pull_requests: bool,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FeedTokenRecord {
    pub(crate) id: String,
    pub(crate) scope: String,
    pub(crate) owner: Option<String>,
    pub(crate) repository: Option<String>,
    pub(crate) created_at: i64,
    pub(crate) revoked_at: Option<i64>,
}

pub(crate) struct ActivityEventRecord {
    pub(crate) repository: RepositoryRecord,
    pub(crate) event: RepositoryEventRecord,
}

pub(crate) struct TokenFeedPage {
    pub(crate) scope: String,
    pub(crate) username: String,
    pub(crate) target: Option<String>,
    pub(crate) events: Vec<ActivityEventRecord>,
}

pub(crate) struct MetadataSearchCandidate {
    pub(crate) kind: String,
    pub(crate) record_id: String,
    pub(crate) owner: String,
    pub(crate) repository: String,
    pub(crate) issue_number: Option<i64>,
    pub(crate) title: Vec<u8>,
    pub(crate) body: Vec<u8>,
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

pub(crate) struct NewAuditEvent<'a> {
    pub(crate) action: &'a str,
    pub(crate) actor: &'a str,
    pub(crate) target: &'a str,
    pub(crate) outcome: &'a str,
    pub(crate) correlation_id: &'a str,
    pub(crate) created_at: i64,
}

pub(crate) struct AuditContext<'a> {
    pub(crate) actor: &'a str,
    pub(crate) correlation_id: &'a str,
    pub(crate) created_at: i64,
}

#[allow(
    dead_code,
    reason = "some integration tests compile storage without the audit CLI"
)]
pub(crate) struct AuditEventRecord {
    pub(crate) id: i64,
    pub(crate) action: String,
    pub(crate) actor: String,
    pub(crate) target: String,
    pub(crate) outcome: String,
    pub(crate) correlation_id: String,
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

#[allow(
    dead_code,
    reason = "some integration tests compile storage without accounts"
)]
fn insert_ssh_key(
    transaction: &rusqlite::Transaction<'_>,
    account_id: i64,
    key: &NewSshKey<'_>,
    created_at: i64,
) -> Result<(), StoreError> {
    match transaction.execute(
        "INSERT INTO ssh_public_key
         (account_id, canonical_key, fingerprint, created_at, label, last_used_at, revoked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
        rusqlite::params![
            account_id,
            key.canonical_key,
            key.fingerprint,
            created_at,
            key.label,
        ],
    ) {
        Ok(1) => Ok(()),
        Err(error) if is_unique_constraint(&error) => Err(StoreError::KeyExists),
        Err(error) => Err(error.into()),
        Ok(_) => unreachable!("an INSERT changes one row"),
    }
}

fn insert_audit_event(
    connection: &Connection,
    event: &NewAuditEvent<'_>,
) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO audit_event
         (action, actor, target, outcome, correlation_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            event.action,
            event.actor,
            event.target,
            event.outcome,
            event.correlation_id,
            event.created_at,
        ],
    )?;
    Ok(())
}

struct RepositoryIssueAccess {
    repository: RepositoryRecord,
    active_actor_id: Option<i64>,
    role: Option<String>,
}

impl RepositoryIssueAccess {
    fn can_read(&self) -> bool {
        self.repository.state == "active"
            && (self.repository.visibility == "public" || self.role.is_some())
    }

    fn can_write_issue(&self, author_account_id: i64) -> bool {
        self.can_read()
            && (self.active_actor_id == Some(author_account_id)
                || matches!(
                    self.role.as_deref(),
                    Some("owner" | "maintainer" | "writer")
                ))
    }

    fn can_maintain(&self) -> bool {
        self.can_read() && matches!(self.role.as_deref(), Some("owner" | "maintainer"))
    }

    fn can_write_repository(&self) -> bool {
        self.can_read()
            && matches!(
                self.role.as_deref(),
                Some("owner" | "maintainer" | "writer")
            )
    }
}

struct StoredIssue {
    issue: IssueRecord,
    author_account_id: i64,
}

fn repository_issue_access(
    connection: &Connection,
    owner: &str,
    repository: &str,
    actor: Option<&str>,
) -> Result<RepositoryIssueAccess, StoreError> {
    let result = connection.query_row(
        "SELECT repository.id, owner.username, repository.slug,
                repository.visibility, repository.state, repository.object_format,
                repository.created_at, repository.archived_at,
                CASE WHEN actor.state = 'active' THEN actor.id END,
                CASE
                    WHEN actor.state != 'active' THEN NULL
                    WHEN actor.id = repository.owner_account_id THEN 'owner'
                    ELSE repository_collaborator.role
                END
         FROM repository
         JOIN account AS owner ON owner.id = repository.owner_account_id
         LEFT JOIN account AS actor ON actor.username = ?3
         LEFT JOIN repository_collaborator
           ON repository_collaborator.repository_id = repository.id
          AND repository_collaborator.account_id = actor.id
         WHERE owner.username = ?1 AND repository.slug = ?2",
        rusqlite::params![owner, repository, actor],
        |row| {
            Ok(RepositoryIssueAccess {
                repository: repository_from_row(row)?,
                active_actor_id: row.get(8)?,
                role: row.get(9)?,
            })
        },
    );
    match result {
        Ok(access) => Ok(access),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(StoreError::RepositoryNotFound(
            owner.to_owned(),
            repository.to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_pull_request_intent(
    transaction: &rusqlite::Transaction<'_>,
    intent: &NewPullRequestRefIntent<'_>,
    repository_id: &str,
    author_account_id: i64,
    pull_request_number: i64,
    revision_number: i64,
    old_head_object_id: Option<&str>,
    operation: &str,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO pull_request_ref_intent
         (id, repository_id, pull_request_id, pull_request_number, revision_number,
          operation, title, body, author_account_id, actor, base_ref, head_ref,
          base_object_id, old_head_object_id, head_object_id, state, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                 ?13, ?14, ?15, 'pending', ?16)",
        rusqlite::params![
            intent.id,
            repository_id,
            intent.pull_request_id,
            pull_request_number,
            revision_number,
            operation,
            intent.title,
            intent.body,
            author_account_id,
            intent.actor,
            intent.base_ref,
            intent.head_ref,
            intent.base_object_id,
            old_head_object_id,
            intent.head_object_id,
            intent.created_at,
        ],
    )?;
    Ok(())
}

fn pull_request_intent(
    connection: &Connection,
    id: &str,
) -> Result<PullRequestRefIntentRecord, StoreError> {
    connection
        .query_row(
            "SELECT id, repository_id, pull_request_id, pull_request_number,
                    revision_number, operation, title, body, author_account_id, actor,
                    base_ref, head_ref, base_object_id, old_head_object_id,
                    head_object_id, state, created_at
             FROM pull_request_ref_intent WHERE id = ?1",
            [id],
            pull_request_intent_from_row,
        )
        .optional()?
        .ok_or_else(|| StoreError::PullRequestIntentState(id.to_owned()))
}

fn pull_request_intent_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PullRequestRefIntentRecord> {
    Ok(PullRequestRefIntentRecord {
        id: row.get(0)?,
        repository_id: row.get(1)?,
        pull_request_id: row.get(2)?,
        pull_request_number: row.get(3)?,
        revision_number: row.get(4)?,
        operation: row.get(5)?,
        title: row.get(6)?,
        body: row.get(7)?,
        author_account_id: row.get(8)?,
        actor: row.get(9)?,
        base_ref: row.get(10)?,
        head_ref: row.get(11)?,
        base_object_id: row.get(12)?,
        old_head_object_id: row.get(13)?,
        head_object_id: row.get(14)?,
        state: row.get(15)?,
        created_at: row.get(16)?,
    })
}

fn pull_request_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PullRequestRecord> {
    Ok(PullRequestRecord {
        id: row.get(0)?,
        number: row.get(1)?,
        title: row.get(2)?,
        body: row.get(3)?,
        state: row.get(4)?,
        author: row.get(5)?,
        base_ref: row.get(6)?,
        head_ref: row.get(7)?,
        base_object_id: row.get(8)?,
        head_object_id: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn validate_feed_scope(scope: &str, repository: Option<(&str, &str)>) -> Result<(), StoreError> {
    match (scope, repository) {
        ("repository", Some(_)) | ("watched" | "assignments" | "mentions", None) => Ok(()),
        _ => Err(StoreError::InvalidFeedScope),
    }
}

fn feed_token_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FeedTokenRecord> {
    Ok(FeedTokenRecord {
        id: row.get(0)?,
        scope: row.get(1)?,
        owner: row.get(2)?,
        repository: row.get(3)?,
        created_at: row.get(4)?,
        revoked_at: row.get(5)?,
    })
}

fn activity_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActivityEventRecord> {
    Ok(ActivityEventRecord {
        repository: RepositoryRecord {
            id: row.get(0)?,
            owner: row.get(1)?,
            slug: row.get(2)?,
            visibility: row.get(3)?,
            state: row.get(4)?,
            object_format: row.get(5)?,
            created_at: row.get(6)?,
            archived_at: row.get(7)?,
        },
        event: RepositoryEventRecord {
            event_id: row.get(8)?,
            sequence: row.get(9)?,
            kind: row.get(10)?,
            actor: row.get(11)?,
            ref_name: row.get(12)?,
            old_target: row.get(13)?,
            new_target: row.get(14)?,
            payload_version: row.get(15)?,
            payload: row.get(16)?,
            created_at: row.get(17)?,
        },
    })
}

const ACTIVITY_SELECT: &str = "SELECT repository.id, owner.username, repository.slug,
            repository.visibility, repository.state, repository.object_format,
            repository.created_at, repository.archived_at,
            repository_event.event_id, repository_event.sequence,
            repository_event.kind, repository_event.actor, repository_event.ref_name,
            repository_event.old_target, repository_event.new_target,
            repository_event.payload_version, repository_event.payload,
            repository_event.created_at
     FROM repository_event
     JOIN repository ON repository.id = repository_event.repository_id
     JOIN account AS owner ON owner.id = repository.owner_account_id";

fn token_repository_events(
    connection: &Connection,
    repository_id: &str,
    account_id: i64,
    limit: i64,
) -> Result<Vec<ActivityEventRecord>, StoreError> {
    let sql = format!(
        "{ACTIVITY_SELECT}
         WHERE repository.id = ?1 AND repository.state = 'active'
           AND (repository.visibility = 'public'
                OR repository.owner_account_id = ?2
                OR EXISTS (
                    SELECT 1 FROM repository_collaborator
                    WHERE repository_collaborator.repository_id = repository.id
                      AND repository_collaborator.account_id = ?2
                ))
         ORDER BY repository_event.sequence DESC LIMIT ?3"
    );
    let mut statement = connection.prepare(&sql)?;
    statement
        .query_map(
            rusqlite::params![repository_id, account_id, limit],
            activity_from_row,
        )?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn watched_feed_events(
    connection: &Connection,
    account_id: i64,
    limit: i64,
) -> Result<Vec<ActivityEventRecord>, StoreError> {
    let sql = format!(
        "{ACTIVITY_SELECT}
         JOIN watch
           ON watch.repository_id = repository.id AND watch.account_id = ?1
         WHERE repository.state = 'active'
           AND (repository.visibility = 'public'
                OR repository.owner_account_id = ?1
                OR EXISTS (
                    SELECT 1 FROM repository_collaborator
                    WHERE repository_collaborator.repository_id = repository.id
                      AND repository_collaborator.account_id = ?1
                ))
           AND ((watch.pushes = 1 AND repository_event.kind IN
                    ('push', 'ref-created', 'ref-updated', 'ref-deleted',
                     'tag-created', 'tag-updated', 'tag-deleted'))
                OR (watch.issues = 1 AND repository_event.kind LIKE 'issue-%')
                OR (watch.pull_requests = 1
                    AND repository_event.kind LIKE 'pull-request-%'))
         ORDER BY repository_event.created_at DESC, repository_event.event_id DESC
         LIMIT ?2"
    );
    let mut statement = connection.prepare(&sql)?;
    statement
        .query_map(rusqlite::params![account_id, limit], activity_from_row)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn assignment_feed_events(
    connection: &Connection,
    account_id: i64,
    username: &str,
    limit: i64,
) -> Result<Vec<ActivityEventRecord>, StoreError> {
    let sql = format!(
        "{ACTIVITY_SELECT}
         WHERE repository.state = 'active'
           AND repository_event.kind = 'issue-assigned'
           AND json_extract(repository_event.payload, '$.assignee') = ?2
           AND (repository.visibility = 'public'
                OR repository.owner_account_id = ?1
                OR EXISTS (
                    SELECT 1 FROM repository_collaborator
                    WHERE repository_collaborator.repository_id = repository.id
                      AND repository_collaborator.account_id = ?1
                ))
         ORDER BY repository_event.created_at DESC, repository_event.event_id DESC
         LIMIT ?3"
    );
    let mut statement = connection.prepare(&sql)?;
    statement
        .query_map(
            rusqlite::params![account_id, username, limit],
            activity_from_row,
        )?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn mention_feed_events(
    connection: &Connection,
    account_id: i64,
    username: &str,
    limit: i64,
) -> Result<Vec<ActivityEventRecord>, StoreError> {
    let scan_limit = limit.saturating_mul(50).min(1_000);
    let sql = format!(
        "{ACTIVITY_SELECT}
         WHERE repository.state = 'active'
           AND repository_event.kind IN
               ('issue-created', 'issue-edited', 'issue-commented')
           AND (repository.visibility = 'public'
                OR repository.owner_account_id = ?1
                OR EXISTS (
                    SELECT 1 FROM repository_collaborator
                    WHERE repository_collaborator.repository_id = repository.id
                      AND repository_collaborator.account_id = ?1
                ))
         ORDER BY repository_event.created_at DESC, repository_event.event_id DESC
         LIMIT ?2"
    );
    let mut statement = connection.prepare(&sql)?;
    let candidates = statement
        .query_map(rusqlite::params![account_id, scan_limit], activity_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    let limit = usize::try_from(limit).map_err(|_| StoreError::EventLimit)?;
    Ok(candidates
        .into_iter()
        .filter(|record| event_mentions(&record.event, username))
        .take(limit)
        .collect())
}

fn event_mentions(event: &RepositoryEventRecord, username: &str) -> bool {
    if event.payload_version != event::PAYLOAD_VERSION {
        return false;
    }
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(&event.payload) else {
        return false;
    };
    let Some(body) = payload.get("body").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let mention = format!("@{username}");
    body.match_indices(&mention).any(|(start, _)| {
        let before = body[..start].chars().next_back();
        let after = body[start + mention.len()..].chars().next();
        !before.is_some_and(is_username_character) && !after.is_some_and(is_username_character)
    })
}

fn is_username_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-'
}

fn find_issue(
    connection: &Connection,
    repository: &RepositoryRecord,
    owner: &str,
    slug: &str,
    number: i64,
) -> Result<StoredIssue, StoreError> {
    let result = connection.query_row(
        "SELECT issue.id, issue.number, issue.title, issue.body, issue.state,
                account.username, issue.created_at, issue.updated_at, issue.closed_at,
                issue.author_account_id
         FROM issue
         JOIN account ON account.id = issue.author_account_id
         WHERE issue.repository_id = ?1 AND issue.number = ?2",
        rusqlite::params![repository.id, number],
        |row| {
            Ok(StoredIssue {
                issue: issue_from_row(row)?,
                author_account_id: row.get(9)?,
            })
        },
    );
    match result {
        Ok(issue) => Ok(issue),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(StoreError::IssueNotFound(
            owner.to_owned(),
            slug.to_owned(),
            number,
        )),
        Err(error) => Err(error.into()),
    }
}

fn issue_mutation_context(
    connection: &Connection,
    owner: &str,
    repository: &str,
    number: i64,
    actor: &str,
) -> Result<(RepositoryIssueAccess, StoredIssue), StoreError> {
    let access = repository_issue_access(connection, owner, repository, Some(actor))?;
    if !access.can_read() {
        return Err(StoreError::IssueHidden);
    }
    if access.active_actor_id.is_none() {
        return Err(StoreError::IssueDenied);
    }
    let issue = find_issue(connection, &access.repository, owner, repository, number)?;
    Ok((access, issue))
}

fn issue_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<IssueRecord> {
    Ok(IssueRecord {
        id: row.get(0)?,
        number: row.get(1)?,
        title: row.get(2)?,
        body: row.get(3)?,
        state: row.get(4)?,
        author: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        closed_at: row.get(8)?,
    })
}

fn issue_names(
    connection: &Connection,
    sql: &str,
    issue_id: &str,
) -> Result<Vec<String>, StoreError> {
    let mut statement = connection.prepare(sql)?;
    statement
        .query_map([issue_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn insert_issue_event(
    transaction: &rusqlite::Transaction<'_>,
    repository_id: &str,
    issue_id: &str,
    actor: &str,
    created_at: i64,
    event: &event::VersionedEvent,
) -> Result<(), StoreError> {
    insert_domain_event(
        transaction,
        &NewDomainEvent {
            repository_id,
            source_intent_id: None,
            source_ordinal: None,
            issue_id: Some(issue_id),
            pull_request_id: None,
            event,
            actor,
            ref_name: None,
            old_target: None,
            new_target: None,
            created_at,
        },
    )
}

struct NewDomainEvent<'a> {
    repository_id: &'a str,
    source_intent_id: Option<&'a str>,
    source_ordinal: Option<i64>,
    issue_id: Option<&'a str>,
    pull_request_id: Option<&'a str>,
    event: &'a event::VersionedEvent,
    actor: &'a str,
    ref_name: Option<&'a [u8]>,
    old_target: Option<&'a str>,
    new_target: Option<&'a str>,
    created_at: i64,
}

fn insert_domain_event(
    transaction: &rusqlite::Transaction<'_>,
    event: &NewDomainEvent<'_>,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO repository_event
         (event_id, repository_id, sequence, source_intent_id, source_ordinal,
          issue_id, pull_request_id, kind, actor, ref_name, old_target, new_target,
          payload_version, payload,
          created_at)
         VALUES (
             lower(hex(randomblob(16))),
             ?1,
             (SELECT COALESCE(MAX(sequence), 0) + 1
              FROM repository_event WHERE repository_id = ?1),
             ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
         )",
        rusqlite::params![
            event.repository_id,
            event.source_intent_id,
            event.source_ordinal,
            event.issue_id,
            event.pull_request_id,
            event.event.kind.as_str(),
            event.actor,
            event.ref_name,
            event.old_target,
            event.new_target,
            event::PAYLOAD_VERSION,
            event.event.payload,
            event.created_at,
        ],
    )?;
    Ok(())
}

fn end_sessions(
    transaction: &rusqlite::Transaction<'_>,
    account_id: i64,
    ended_at: i64,
) -> Result<(), StoreError> {
    transaction.execute(
        "UPDATE web_session SET ended_at = ?2
         WHERE account_id = ?1 AND ended_at IS NULL",
        rusqlite::params![account_id, ended_at],
    )?;
    Ok(())
}

fn insert_push_events(
    transaction: &rusqlite::Transaction<'_>,
    intent_id: &str,
    repository_path: &str,
    actor: &str,
    initial_bytes: &[u8],
    proposed_bytes: &[u8],
    created_at: i64,
) -> Result<(), StoreError> {
    let Some(repository_id) = managed_repository_id(repository_path) else {
        return Ok(());
    };
    let exists = transaction
        .query_row(
            "SELECT id FROM repository WHERE id = ?1",
            [repository_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if exists.is_none() {
        return Ok(());
    }

    let initial = parse_event_refs(initial_bytes)?;
    let proposed = parse_event_refs(proposed_bytes)?;
    if initial.len() != proposed.len() {
        return Err(StoreError::EventPayload);
    }
    let push = event::push(intent_id);
    insert_domain_event(
        transaction,
        &NewDomainEvent {
            repository_id,
            source_intent_id: Some(intent_id),
            source_ordinal: Some(0),
            issue_id: None,
            pull_request_id: None,
            event: &push,
            actor,
            ref_name: None,
            old_target: None,
            new_target: None,
            created_at,
        },
    )?;
    for (index, ((old, old_name), (new, new_name))) in initial.into_iter().zip(proposed).enumerate()
    {
        if old_name != new_name || (is_null_id(&old) && is_null_id(&new)) {
            return Err(StoreError::EventPayload);
        }
        let tag = if old_name.starts_with(b"refs/tags/") {
            true
        } else if old_name.starts_with(b"refs/heads/") {
            false
        } else {
            return Err(StoreError::EventPayload);
        };
        let kind = if is_null_id(&old) {
            if tag {
                event::EventKind::TagCreated
            } else {
                event::EventKind::RefCreated
            }
        } else if is_null_id(&new) {
            if tag {
                event::EventKind::TagDeleted
            } else {
                event::EventKind::RefDeleted
            }
        } else if tag {
            event::EventKind::TagUpdated
        } else {
            event::EventKind::RefUpdated
        };
        let old_target = (!is_null_id(&old)).then_some(old);
        let new_target = (!is_null_id(&new)).then_some(new);
        let ordinal = i64::try_from(index + 1).map_err(|_| StoreError::EventPayload)?;
        let event = event::reference(
            kind,
            &old_name,
            old_target.as_deref(),
            new_target.as_deref(),
        );
        insert_domain_event(
            transaction,
            &NewDomainEvent {
                repository_id,
                source_intent_id: Some(intent_id),
                source_ordinal: Some(ordinal),
                issue_id: None,
                pull_request_id: None,
                event: &event,
                actor,
                ref_name: Some(&old_name),
                old_target: old_target.as_deref(),
                new_target: new_target.as_deref(),
                created_at,
            },
        )?;
    }
    insert_audit_event(
        transaction,
        &NewAuditEvent {
            action: "ref.update",
            actor,
            target: repository_id,
            outcome: "success",
            correlation_id: intent_id,
            created_at,
        },
    )?;
    Ok(())
}

fn managed_repository_id(repository_path: &str) -> Option<&str> {
    let name = Path::new(repository_path).file_name()?.to_str()?;
    let id = name.strip_suffix(".git")?;
    (id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(id)
}

fn parse_event_refs(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
    let mut references = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Some(space) = line.iter().position(|byte| *byte == b' ') else {
            return Err(StoreError::EventPayload);
        };
        let id = std::str::from_utf8(&line[..space]).map_err(|_| StoreError::EventPayload)?;
        if !matches!(id.len(), 40 | 64) || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(StoreError::EventPayload);
        }
        let name = line[space + 1..].to_vec();
        if name.is_empty() {
            return Err(StoreError::EventPayload);
        }
        references.push((id.to_owned(), name));
    }
    Ok(references)
}

fn is_null_id(id: &str) -> bool {
    id.bytes().all(|byte| byte == b'0')
}

fn require_one_intent(id: &str, changed: usize) -> Result<(), StoreError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::IntentState(id.to_owned()))
    }
}

fn active_account_id(connection: &Connection, username: &str) -> Result<i64, StoreError> {
    let result = connection.query_row(
        "SELECT id FROM account WHERE username = ?1 AND state = 'active'",
        [username],
        |row| row.get(0),
    );
    match result {
        Ok(id) => Ok(id),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Err(StoreError::AccountNotFound(username.to_owned()))
        }
        Err(error) => Err(error.into()),
    }
}

fn repository_state_error(
    transaction: &rusqlite::Transaction<'_>,
    owner_id: i64,
    owner: &str,
    slug: &str,
) -> Result<StoreError, StoreError> {
    let state = transaction.query_row(
        "SELECT state FROM repository WHERE owner_account_id = ?1 AND slug = ?2",
        rusqlite::params![owner_id, slug],
        |row| row.get::<_, String>(0),
    );
    match state {
        Ok(state) if state == "archived" => Ok(StoreError::RepositoryArchived(
            owner.to_owned(),
            slug.to_owned(),
        )),
        Ok(_) => unreachable!("repository state has a database constraint"),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(StoreError::RepositoryNotFound(
            owner.to_owned(),
            slug.to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

fn repository_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RepositoryRecord> {
    Ok(RepositoryRecord {
        id: row.get(0)?,
        owner: row.get(1)?,
        slug: row.get(2)?,
        visibility: row.get(3)?,
        state: row.get(4)?,
        object_format: row.get(5)?,
        created_at: row.get(6)?,
        archived_at: row.get(7)?,
    })
}

fn is_unique_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                || code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
    )
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
