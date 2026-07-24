#[allow(dead_code, reason = "the Web session test uses one shared test helper")]
mod support;

#[allow(
    dead_code,
    reason = "the Web session test uses part of account management"
)]
#[path = "../src/account.rs"]
mod account;
#[allow(dead_code, reason = "the Web session test uses part of authentication")]
#[path = "../src/auth.rs"]
mod auth;
#[path = "../src/session.rs"]
mod session;
#[allow(
    dead_code,
    reason = "the Web session test does not use each store operation"
)]
#[path = "../src/store/mod.rs"]
mod store;

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use support::create_ssh_key_fixture;
use tempfile::TempDir;
use url::Url;

use account::AccountService;
use auth::SshPublicKey;
use session::{SessionError, WebLoginService};
use store::{InitialAdministrator, Store, StoreError};

#[test]
fn persists_one_time_challenges_and_opaque_revocable_sessions() {
    let directory = TempDir::new().expect("create a Web session directory");
    let database = directory.path().join("tit.sqlite3");
    let private_key = directory.path().join("identity");
    create_ssh_key_fixture(&private_key);
    let public_key =
        fs::read_to_string(private_key.with_extension("pub")).expect("read the SSH public key");
    let parsed = SshPublicKey::parse(&public_key).expect("parse the SSH public key");
    let mut store = Store::open(&database).expect("create the database");
    store
        .create_initial_administrator(&InitialAdministrator {
            username: "alice",
            canonical_key: parsed.canonical(),
            fingerprint: parsed.fingerprint(),
            recovery_hash: &[1; 32],
            created_at: now(),
        })
        .expect("create the account");

    let origin = Url::parse("https://tit.example/").expect("parse the origin");
    let login = WebLoginService::new(database.clone(), &origin).expect("create the login service");
    let issued = login.issue("alice").expect("issue a login challenge");
    let signature = sign(directory.path(), &private_key, &issued.challenge);
    let unknown_key = directory.path().join("unknown-identity");
    create_ssh_key_fixture(&unknown_key);
    let unknown_signature = sign(directory.path(), &unknown_key, &issued.challenge);

    let restarted =
        WebLoginService::new(database.clone(), &origin).expect("restart the login service");
    assert!(matches!(
        restarted.verify(
            "alice",
            &issued.challenge,
            &unknown_signature,
            &issued.login_csrf,
            "unknown-key",
        ),
        Err(SessionError::Store(StoreError::InvalidLoginChallenge))
    ));
    let session = restarted
        .verify(
            "alice",
            &issued.challenge,
            &signature,
            &issued.login_csrf,
            "test-login",
        )
        .expect("verify the login challenge after restart");
    assert_eq!(
        restarted
            .authenticate(&session.token, Some(&session.csrf))
            .expect("authenticate the Web session")
            .username,
        "alice"
    );
    assert!(matches!(
        restarted.authenticate(&session.token, Some(&"0".repeat(64))),
        Err(SessionError::Store(StoreError::InvalidSession))
    ));
    assert!(matches!(
        restarted.verify(
            "alice",
            &issued.challenge,
            &signature,
            &issued.login_csrf,
            "test-replay",
        ),
        Err(SessionError::Store(StoreError::InvalidLoginChallenge))
    ));

    let connection = Store::open(&database).expect("open the database");
    let (session_hash, csrf_hash): (Vec<u8>, Vec<u8>) = connection
        .connection()
        .query_row(
            "SELECT session_hash, csrf_hash FROM web_session",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read stored session hashes");
    assert_eq!(
        session_hash,
        Sha256::digest(session.token.as_bytes()).as_slice()
    );
    assert_eq!(
        csrf_hash,
        Sha256::digest(session.csrf.as_bytes()).as_slice()
    );
    assert_ne!(session_hash, session.token.as_bytes());

    let second_key = directory.path().join("second-identity");
    create_ssh_key_fixture(&second_key);
    let second_public = fs::read_to_string(second_key.with_extension("pub"))
        .expect("read the second SSH public key");
    AccountService::new(database.clone())
        .add_key("alice", "second", &second_public, "alice", "test")
        .expect("change account privileges");
    assert!(matches!(
        restarted.authenticate(&session.token, None),
        Err(SessionError::Store(StoreError::InvalidSession))
    ));

    let next = restarted.issue("alice").expect("issue another challenge");
    let next_signature = sign(directory.path(), &private_key, &next.challenge);
    let next_session = restarted
        .verify(
            "alice",
            &next.challenge,
            &next_signature,
            &next.login_csrf,
            "test-login",
        )
        .expect("create another session");
    restarted.end_all("alice").expect("end all sessions");
    assert!(matches!(
        restarted.authenticate(&next_session.token, None),
        Err(SessionError::Store(StoreError::InvalidSession))
    ));
}

#[test]
fn binds_ssh_approval_to_one_browser_and_consumes_it_once() {
    let directory = TempDir::new().expect("create a Web session directory");
    let database = directory.path().join("tit.sqlite3");
    let private_key = directory.path().join("identity");
    create_ssh_key_fixture(&private_key);
    let public_key =
        fs::read_to_string(private_key.with_extension("pub")).expect("read the SSH public key");
    let parsed = SshPublicKey::parse(&public_key).expect("parse the SSH public key");
    Store::open(&database)
        .expect("create the database")
        .create_initial_administrator(&InitialAdministrator {
            username: "alice",
            canonical_key: parsed.canonical(),
            fingerprint: parsed.fingerprint(),
            recovery_hash: &[2; 32],
            created_at: now(),
        })
        .expect("create the account");
    let origin = Url::parse("https://tit.example/").expect("parse the origin");
    let login = WebLoginService::new(database.clone(), &origin).expect("create the login service");
    let approval = login.issue_approval().expect("issue an SSH approval");

    assert!(matches!(
        login.complete_approval(&approval.secret, &approval.login_csrf, "pending"),
        Err(SessionError::Store(StoreError::LoginApprovalPending))
    ));
    assert!(matches!(
        login.complete_approval(&approval.secret, &"0".repeat(64), "wrong-browser"),
        Err(SessionError::Store(StoreError::InvalidLoginApproval))
    ));
    let mut changed_secret = approval.secret.clone();
    changed_secret.replace_range(
        ..1,
        if changed_secret.starts_with('0') {
            "1"
        } else {
            "0"
        },
    );
    assert!(matches!(
        login.complete_approval(&changed_secret, &approval.login_csrf, "changed-secret"),
        Err(SessionError::Store(StoreError::InvalidLoginApproval))
    ));
    let restarted =
        WebLoginService::new(database.clone(), &origin).expect("restart the login service");
    let approved = restarted
        .approve(&approval.secret, "alice", parsed.fingerprint())
        .expect("approve the browser login");
    assert_eq!(approved.origin, "https://tit.example");
    assert_eq!(approved.username, "alice");
    assert!(matches!(
        restarted.approve(&approval.secret, "alice", parsed.fingerprint()),
        Err(SessionError::Store(StoreError::InvalidLoginApproval))
    ));

    let login = Arc::new(restarted);
    let barrier = Arc::new(Barrier::new(8));
    let workers = (0..8)
        .map(|index| {
            let login = Arc::clone(&login);
            let barrier = Arc::clone(&barrier);
            let secret = approval.secret.clone();
            let csrf = approval.login_csrf.clone();
            thread::spawn(move || {
                barrier.wait();
                login
                    .complete_approval(&secret, &csrf, &format!("consume-{index}"))
                    .is_ok()
            })
        })
        .collect::<Vec<_>>();
    let successes = workers
        .into_iter()
        .map(|worker| worker.join().expect("join an approval consumer"))
        .filter(|success| *success)
        .count();
    assert_eq!(successes, 1);

    let revoked = login
        .issue_approval()
        .expect("issue a revoked-key approval");
    Store::open(&database)
        .expect("open the database")
        .connection()
        .execute(
            "UPDATE ssh_public_key SET revoked_at = ?1 WHERE fingerprint = ?2",
            rusqlite::params![now(), parsed.fingerprint()],
        )
        .expect("revoke the login key");
    assert!(matches!(
        login.approve(&revoked.secret, "alice", parsed.fingerprint()),
        Err(SessionError::Store(StoreError::LoginIdentity))
    ));
    Store::open(&database)
        .expect("open the database")
        .connection()
        .execute(
            "UPDATE ssh_public_key SET revoked_at = NULL WHERE fingerprint = ?1",
            [parsed.fingerprint()],
        )
        .expect("restore the login key");

    let suspended = login
        .issue_approval()
        .expect("issue a suspended-account approval");
    Store::open(&database)
        .expect("open the database")
        .connection()
        .execute("UPDATE account SET state = 'suspended'", [])
        .expect("suspend the account");
    assert!(matches!(
        login.approve(&suspended.secret, "alice", parsed.fingerprint()),
        Err(SessionError::Store(StoreError::LoginIdentity))
    ));
    Store::open(&database)
        .expect("open the database")
        .connection()
        .execute("UPDATE account SET state = 'active'", [])
        .expect("restore the account");

    let expired = login.issue_approval().expect("issue an expiring approval");
    Store::open(&database)
        .expect("open the database")
        .connection()
        .execute(
            "UPDATE ssh_login_approval SET created_at = 0, expires_at = 1
             WHERE approved_at IS NULL",
            [],
        )
        .expect("expire pending approvals");
    assert!(matches!(
        login.approve(&expired.secret, "alice", parsed.fingerprint()),
        Err(SessionError::Store(StoreError::InvalidLoginApproval))
    ));
}

fn sign(directory: &Path, private_key: &Path, challenge: &str) -> String {
    let nonce = challenge
        .lines()
        .find_map(|line| line.strip_prefix("nonce="))
        .expect("find the challenge nonce");
    let key_name = private_key
        .file_name()
        .and_then(|name| name.to_str())
        .expect("read the private-key name");
    let challenge_path = directory.join(format!("login-{nonce}-{key_name}.challenge"));
    fs::write(&challenge_path, challenge).expect("write the challenge");
    let output = Command::new("ssh-keygen")
        .args(["-q", "-Y", "sign", "-f"])
        .arg(private_key)
        .args(["-n", "tit-auth"])
        .arg(&challenge_path)
        .output()
        .expect("sign the challenge");
    assert!(
        output.status.success(),
        "cannot sign the challenge: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::read_to_string(challenge_path.with_extension("challenge.sig"))
        .expect("read the SSH signature")
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("read the clock")
        .as_secs()
        .try_into()
        .expect("convert the clock")
}
