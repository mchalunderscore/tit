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
    let issued = login
        .issue("alice", &public_key)
        .expect("issue a login challenge");
    let signature = sign(directory.path(), &private_key, &issued.challenge);

    let restarted =
        WebLoginService::new(database.clone(), &origin).expect("restart the login service");
    let session = restarted
        .verify(
            "alice",
            &issued.public_key,
            &issued.challenge,
            &signature,
            &issued.login_csrf,
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
            &issued.public_key,
            &issued.challenge,
            &signature,
            &issued.login_csrf,
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
        .add_key("alice", "second", &second_public)
        .expect("change account privileges");
    assert!(matches!(
        restarted.authenticate(&session.token, None),
        Err(SessionError::Store(StoreError::InvalidSession))
    ));

    let next = restarted
        .issue("alice", &public_key)
        .expect("issue another challenge");
    let next_signature = sign(directory.path(), &private_key, &next.challenge);
    let next_session = restarted
        .verify(
            "alice",
            &next.public_key,
            &next.challenge,
            &next_signature,
            &next.login_csrf,
        )
        .expect("create another session");
    restarted.end_all("alice").expect("end all sessions");
    assert!(matches!(
        restarted.authenticate(&next_session.token, None),
        Err(SessionError::Store(StoreError::InvalidSession))
    ));
}

fn sign(directory: &Path, private_key: &Path, challenge: &str) -> String {
    let nonce = challenge
        .lines()
        .find_map(|line| line.strip_prefix("nonce="))
        .expect("find the challenge nonce");
    let challenge_path = directory.join(format!("login-{nonce}.challenge"));
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
