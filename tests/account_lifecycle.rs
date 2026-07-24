#[path = "../src/account.rs"]
mod account;
#[allow(
    dead_code,
    reason = "the account test uses only SSH public-key parsing"
)]
#[path = "../src/auth.rs"]
mod auth;
#[allow(
    dead_code,
    reason = "the account test does not use every store operation"
)]
#[path = "../src/store/mod.rs"]
mod store;

use rand::rng;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, PrivateKey};
use tempfile::TempDir;

use account::{AccountError, AccountService};
use store::{Store, StoreError};

#[test]
fn invitation_signup_key_and_recovery_lifecycle_is_atomic() {
    let directory = TempDir::new().expect("create an account directory");
    let database = directory.path().join("tit.sqlite3");
    Store::open(&database).expect("create the account database");
    let accounts = AccountService::new(database.clone());
    let first_key = public_key();
    let second_key = public_key();
    let third_key = public_key();

    let invitation = accounts.issue_invitation().expect("issue an invitation");
    assert!(invitation.starts_with("tit-invite-v1:"));
    let stored_invitation: Vec<u8> = Store::open(&database)
        .expect("open the account database")
        .connection()
        .query_row("SELECT code_hash FROM signup_invitation", [], |row| {
            row.get(0)
        })
        .expect("read the invitation hash");
    assert_eq!(stored_invitation.len(), 32);
    assert_ne!(stored_invitation, invitation.as_bytes());

    let recovery = accounts
        .signup(&invitation, "alice", &first_key, "test")
        .expect("create the account");
    accounts
        .update_profile(
            "alice",
            "A small profile.\nSecond line.",
            "alice@example.test",
        )
        .expect("update the public profile");
    let profile = accounts.profile("alice").expect("read the public profile");
    assert_eq!(profile.bio, "A small profile.\nSecond line.");
    assert_eq!(profile.contact_email, "alice@example.test");
    assert!(matches!(
        accounts.update_profile("alice", "profile", "not-an-email"),
        Err(AccountError::InvalidProfile)
    ));
    Store::open(&database)
        .expect("open the account database")
        .create_feed_token("alice", &[7; 32], 1)
        .expect("create a feed token");
    assert!(recovery.starts_with("tit-recovery-v1:"));
    assert!(matches!(
        accounts.signup(&invitation, "bob", &second_key, "test"),
        Err(AccountError::Store(StoreError::InvalidInvitation))
    ));
    let stored_recovery: Vec<u8> = Store::open(&database)
        .expect("open the account database")
        .connection()
        .query_row(
            "SELECT credential_hash FROM recovery_credential",
            [],
            |row| row.get(0),
        )
        .expect("read the recovery hash");
    assert_eq!(stored_recovery.len(), 32);
    assert_ne!(stored_recovery, recovery.as_bytes());

    let second_fingerprint = accounts
        .add_key("alice", "workstation", &second_key, "alice", "test")
        .expect("add a second key");
    let first_fingerprint: String = Store::open(&database)
        .expect("open the account database")
        .connection()
        .query_row(
            "SELECT fingerprint FROM ssh_public_key WHERE label = 'initial'",
            [],
            |row| row.get(0),
        )
        .expect("read the first fingerprint");
    accounts
        .revoke_key("alice", &first_fingerprint, "alice", "test")
        .expect("revoke the first key");
    assert!(matches!(
        accounts.revoke_key("alice", &second_fingerprint, "alice", "test"),
        Err(AccountError::Store(StoreError::LastKey))
    ));

    let replacement = accounts
        .recover("alice", &recovery, &third_key, "test")
        .expect("recover the account");
    assert_eq!(
        active_feed_tokens(&database, "alice"),
        0,
        "recovery must revoke active feed tokens"
    );
    assert!(matches!(
        accounts.recover("alice", &recovery, &first_key, "test"),
        Err(AccountError::Store(StoreError::InvalidRecovery))
    ));
    accounts
        .recover("alice", &replacement, &first_key, "test")
        .expect("use the rotated recovery code");
    assert_eq!(
        Store::open(&database)
            .expect("open the account database")
            .active_ssh_public_keys()
            .expect("list active SSH keys"),
        vec![
            auth::SshPublicKey::parse(&first_key)
                .expect("parse the first key")
                .canonical()
                .to_owned()
        ]
    );
    let audits = Store::open(&database)
        .expect("open the account database")
        .audit_events(20)
        .expect("read account audit history");
    assert!(
        audits
            .iter()
            .any(|event| event.action == "key.add" && event.outcome == "success")
    );
    assert!(
        audits
            .iter()
            .any(|event| event.action == "key.revoke" && event.outcome == "failure")
    );
    assert!(
        audits
            .iter()
            .any(|event| event.action == "account.recover" && event.outcome == "success")
    );
    for event in audits {
        assert!(!event.target.contains(&recovery));
        assert!(!event.target.contains(&replacement));
    }
}

#[test]
fn failed_signup_preserves_the_invitation_and_username_reservation() {
    let directory = TempDir::new().expect("create an account directory");
    let database = directory.path().join("tit.sqlite3");
    Store::open(&database).expect("create the account database");
    let accounts = AccountService::new(database.clone());
    let first = accounts.issue_invitation().expect("issue an invitation");
    accounts
        .signup(&first, "alice", &public_key(), "test")
        .expect("create the first account");
    Store::open(&database)
        .expect("open the account database")
        .create_feed_token("alice", &[8; 32], 1)
        .expect("create a feed token");

    let second = accounts.issue_invitation().expect("issue an invitation");
    assert!(matches!(
        accounts.signup(&second, "alice", &public_key(), "test"),
        Err(AccountError::Store(StoreError::UsernameUnavailable(_)))
    ));
    accounts
        .signup(&second, "bob", &public_key(), "test")
        .expect("reuse the invitation after a rolled-back signup");
    accounts
        .suspend("alice", true, "admin-cli", "test")
        .expect("suspend the account");
    assert_eq!(
        active_feed_tokens(&database, "alice"),
        0,
        "suspension must revoke active feed tokens"
    );
    assert_eq!(
        Store::open(&database)
            .expect("open the account database")
            .connection()
            .query_row(
                "SELECT state FROM account WHERE username = 'alice'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("read the account state"),
        "suspended"
    );
    let third = accounts.issue_invitation().expect("issue an invitation");
    assert!(matches!(
        accounts.signup(&third, "alice", &public_key(), "test"),
        Err(AccountError::Store(StoreError::UsernameUnavailable(_)))
    ));
    let consumed: Option<i64> = Store::open(&database)
        .expect("open the account database")
        .connection()
        .query_row(
            "SELECT consumed_at FROM signup_invitation ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("read the invitation")
        .flatten();
    assert_eq!(consumed, None);
}

fn active_feed_tokens(database: &std::path::Path, username: &str) -> i64 {
    Store::open(database)
        .expect("open the account database")
        .connection()
        .query_row(
            "SELECT count(*)
             FROM feed_token
             JOIN account ON account.id = feed_token.account_id
             WHERE account.username = ?1 AND feed_token.revoked_at IS NULL",
            [username],
            |row| row.get(0),
        )
        .expect("count active feed tokens")
}

#[test]
fn expired_invitations_do_not_create_accounts() {
    let directory = TempDir::new().expect("create an account directory");
    let database = directory.path().join("tit.sqlite3");
    let store = Store::open(&database).expect("create the account database");
    let invitation =
        "tit-invite-v1:0000000000000000000000000000000000000000000000000000000000000000";
    let invitation_hash: [u8; 32] = Sha256::digest(invitation.as_bytes()).into();
    store
        .create_signup_invitation(&invitation_hash, 1, 2)
        .expect("store an expired invitation");
    let accounts = AccountService::new(database.clone());
    assert!(matches!(
        accounts.signup(invitation, "alice", &public_key(), "test"),
        Err(AccountError::Store(StoreError::InvalidInvitation))
    ));
    assert_eq!(
        Store::open(&database)
            .expect("open the account database")
            .connection()
            .query_row("SELECT count(*) FROM account", [], |row| row
                .get::<_, i64>(0))
            .expect("count accounts"),
        0
    );
}

fn public_key() -> String {
    PrivateKey::random(&mut rng(), Algorithm::Ed25519)
        .expect("create an SSH key")
        .public_key()
        .to_openssh()
        .expect("encode an SSH public key")
}
