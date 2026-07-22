#[path = "../src/auth.rs"]
mod auth;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;

use auth::{AuthError, LoginChallenges, SshPublicKey};
use tempfile::TempDir;
use url::Url;

const ISSUED_AT: u64 = 1_750_000_000;
const LIFETIME: u64 = 120;
const DSA_PUBLIC_KEY: &str = "ssh-dss AAAAB3NzaC1kc3MAAACBANw9iSUO2UYhFMssjUgW46URqv8bBrDgHeF8HLBOWBvKuXF2Rx2J/XyhgX48SOLMuv0hcPaejlyLarabnF9F2V4dkpPpZSJ+7luHmxEjNxwhsdtg8UteXAWkeCzrQ6MvRJZHcDBjYh56KGvslbFnJsGLXlI4PQCyl6awNImwYGilAAAAFQCJGBU3hZf+QtP9Jh/nbfNlhFu7hwAAAIBHObOQioQVRm3HsVb7mOy3FVKhcLoLO3qoG9gTkd4KeuehtFAC3+rckiX7xSCnE/5BBKdL7VP9WRXac2Nlr9Pwl3e7zPut96wrCHt/TZX6vkfXKkbpUIj5zSqfvyNrWKaYJkfzwAQwrXNS1Hol676Ud/DDEn2oatdEhkS3beWHXAAAAIBgQqaz/YYTRMshzMzYcZ4lqgvgmA55y6v0h39e8HH2A5dwNS6sPUw2jyna+le0dceNRJifFld1J+WYM0vmquSr11DDavgEidOSaXwfMvPPPJqLmbzdtT16N+Gij9U9STQTHPQcQ3xnNNHgQAStzZJbhLOVbDDDo5BO7LMUALDfSA==";

#[test]
fn normalizes_supported_openssh_keys_and_matches_stock_fingerprints() {
    let directory = TempDir::new().expect("create a key directory");
    for fixture in [KeyFixture::Ed25519, KeyFixture::EcdsaP256] {
        let private_key = directory.path().join(fixture.name());
        generate_key(&private_key, fixture);
        let public_key_path = public_key_path(&private_key);
        let encoded = fs::read_to_string(&public_key_path).expect("read the public key");
        let key = SshPublicKey::parse(&encoded).expect("normalize the public key");

        assert_eq!(key.canonical().split_whitespace().count(), 2);
        assert_eq!(key.fingerprint(), stock_fingerprint(&public_key_path));
        assert_eq!(
            SshPublicKey::parse(key.canonical())
                .expect("parse the normalized key")
                .canonical(),
            key.canonical()
        );
    }
}

#[test]
fn rejects_unsupported_and_undersized_keys() {
    let directory = TempDir::new().expect("create a key directory");

    assert!(matches!(
        SshPublicKey::parse(DSA_PUBLIC_KEY),
        Err(AuthError::UnsupportedKeyAlgorithm)
    ));

    let ecdsa_p384 = directory.path().join("ecdsa-p384");
    generate_key(&ecdsa_p384, KeyFixture::EcdsaP384);
    assert!(matches!(
        parse_public_key(&ecdsa_p384),
        Err(AuthError::UnsupportedKeyAlgorithm)
    ));

    let rsa_2048 = directory.path().join("rsa-2048");
    generate_key(&rsa_2048, KeyFixture::Rsa2048);
    assert!(matches!(
        parse_public_key(&rsa_2048),
        Err(AuthError::UndersizedRsa {
            actual: 2_048,
            minimum: 3_072
        })
    ));

    let rsa_3072 = directory.path().join("rsa-3072");
    generate_key(&rsa_3072, KeyFixture::Rsa3072);
    assert!(matches!(
        parse_public_key(&rsa_3072),
        Err(AuthError::UnsupportedKeyAlgorithm)
    ));

    assert!(SshPublicKey::parse("not a key").is_err());
}

#[test]
fn verifies_stock_sshsig_envelopes_for_each_supported_key() {
    let directory = TempDir::new().expect("create a key directory");
    for fixture in [KeyFixture::Ed25519, KeyFixture::EcdsaP256] {
        let private_key = directory.path().join(fixture.name());
        generate_key(&private_key, fixture);
        let key = parse_public_key(&private_key).expect("parse the public key");
        let challenges = issuer("https://tit.example/");
        let challenge = challenges
            .issue("alice", &key, ISSUED_AT, LIFETIME)
            .expect("issue a login challenge");
        let signature = sign(
            &directory,
            fixture.name(),
            &private_key,
            "tit-auth",
            &challenge,
        );

        let verified = challenges
            .verify(&challenge, &signature, "alice", &key, ISSUED_AT + 1)
            .expect("verify the stock SSHSIG envelope");
        assert_eq!(verified.username, "alice");
        assert_eq!(verified.fingerprint, key.fingerprint());
    }
}

#[test]
fn rejects_replay_expiry_wrong_context_and_malformed_envelopes() {
    let directory = TempDir::new().expect("create a key directory");
    let private_key = directory.path().join("ed25519");
    generate_key(&private_key, KeyFixture::Ed25519);
    let key = parse_public_key(&private_key).expect("parse the public key");

    let replay_issuer = issuer("https://tit.example/");
    let replay_challenge = replay_issuer
        .issue("alice", &key, ISSUED_AT, LIFETIME)
        .expect("issue a replay challenge");
    let replay_signature = sign(
        &directory,
        "replay",
        &private_key,
        "tit-auth",
        &replay_challenge,
    );
    replay_issuer
        .verify(
            &replay_challenge,
            &replay_signature,
            "alice",
            &key,
            ISSUED_AT + 1,
        )
        .expect("verify the challenge one time");
    assert!(matches!(
        replay_issuer.verify(
            &replay_challenge,
            &replay_signature,
            "alice",
            &key,
            ISSUED_AT + 1
        ),
        Err(AuthError::ConsumedChallenge)
    ));

    let expired_issuer = issuer("https://tit.example/");
    let expired_challenge = expired_issuer
        .issue("alice", &key, ISSUED_AT, LIFETIME)
        .expect("issue an expiring challenge");
    let expired_signature = sign(
        &directory,
        "expired",
        &private_key,
        "tit-auth",
        &expired_challenge,
    );
    assert!(matches!(
        expired_issuer.verify(
            &expired_challenge,
            &expired_signature,
            "alice",
            &key,
            ISSUED_AT + LIFETIME + 1
        ),
        Err(AuthError::ExpiredChallenge)
    ));

    let namespace_issuer = issuer("https://tit.example/");
    let namespace_challenge = namespace_issuer
        .issue("alice", &key, ISSUED_AT, LIFETIME)
        .expect("issue a namespace challenge");
    let wrong_namespace = sign(
        &directory,
        "namespace",
        &private_key,
        "other",
        &namespace_challenge,
    );
    assert!(matches!(
        namespace_issuer.verify(
            &namespace_challenge,
            &wrong_namespace,
            "alice",
            &key,
            ISSUED_AT + 1
        ),
        Err(AuthError::SignatureVerification(_))
    ));

    let origin_issuer = issuer("https://tit.example/");
    let origin_challenge = origin_issuer
        .issue("alice", &key, ISSUED_AT, LIFETIME)
        .expect("issue an origin challenge");
    let origin_signature = sign(
        &directory,
        "origin",
        &private_key,
        "tit-auth",
        &origin_challenge,
    );
    assert!(matches!(
        issuer("https://other.example/").verify(
            &origin_challenge,
            &origin_signature,
            "alice",
            &key,
            ISSUED_AT + 1
        ),
        Err(AuthError::WrongOrigin)
    ));

    let malformed_issuer = issuer("https://tit.example/");
    let malformed_challenge = malformed_issuer
        .issue("alice", &key, ISSUED_AT, LIFETIME)
        .expect("issue a malformed-envelope challenge");
    assert!(matches!(
        malformed_issuer.verify(
            &malformed_challenge,
            "not an SSHSIG envelope",
            "alice",
            &key,
            ISSUED_AT + 1
        ),
        Err(AuthError::SignatureEnvelope(_))
    ));
}

#[test]
fn rejects_wrong_key_username_and_rsa_keys() {
    let directory = TempDir::new().expect("create a key directory");
    let first_private = directory.path().join("first");
    let second_private = directory.path().join("second");
    generate_key(&first_private, KeyFixture::Ed25519);
    generate_key(&second_private, KeyFixture::Ed25519);
    let first_key = parse_public_key(&first_private).expect("parse the first public key");
    let second_key = parse_public_key(&second_private).expect("parse the second public key");
    let challenges = issuer("https://tit.example/");
    let challenge = challenges
        .issue("alice", &first_key, ISSUED_AT, LIFETIME)
        .expect("issue a key challenge");
    let signature = sign(
        &directory,
        "wrong-key",
        &first_private,
        "tit-auth",
        &challenge,
    );

    assert!(matches!(
        challenges.verify(&challenge, &signature, "alice", &second_key, ISSUED_AT + 1),
        Err(AuthError::WrongKey)
    ));
    assert!(matches!(
        challenges.verify(&challenge, &signature, "bob", &first_key, ISSUED_AT + 1),
        Err(AuthError::WrongUsername)
    ));

    let rsa_private = directory.path().join("rsa");
    generate_key(&rsa_private, KeyFixture::Rsa3072);
    assert!(matches!(
        parse_public_key(&rsa_private),
        Err(AuthError::UnsupportedKeyAlgorithm)
    ));
}

#[test]
fn consumes_a_nonce_atomically() {
    let directory = TempDir::new().expect("create a key directory");
    let private_key = directory.path().join("ed25519");
    generate_key(&private_key, KeyFixture::Ed25519);
    let key = parse_public_key(&private_key).expect("parse the public key");
    let challenges = Arc::new(issuer("https://tit.example/"));
    let challenge = challenges
        .issue("alice", &key, ISSUED_AT, LIFETIME)
        .expect("issue a concurrent challenge");
    let signature = sign(
        &directory,
        "concurrent",
        &private_key,
        "tit-auth",
        &challenge,
    );
    let barrier = Arc::new(Barrier::new(8));

    let workers: Vec<_> = (0..8)
        .map(|_| {
            let challenges = Arc::clone(&challenges);
            let barrier = Arc::clone(&barrier);
            let challenge = challenge.clone();
            let signature = signature.clone();
            let key = key.clone();
            thread::spawn(move || {
                barrier.wait();
                challenges
                    .verify(&challenge, &signature, "alice", &key, ISSUED_AT + 1)
                    .is_ok()
            })
        })
        .collect();

    let successes = workers
        .into_iter()
        .map(|worker| worker.join().expect("join a verifier"))
        .filter(|success| *success)
        .count();
    assert_eq!(successes, 1);
}

#[test]
fn enforces_input_and_active_challenge_limits() {
    let directory = TempDir::new().expect("create a key directory");
    let private_key = directory.path().join("ed25519");
    generate_key(&private_key, KeyFixture::Ed25519);
    let key = parse_public_key(&private_key).expect("parse the public key");

    assert!(matches!(
        SshPublicKey::parse(&"x".repeat(16 * 1024 + 1)),
        Err(AuthError::InputTooLarge("SSH public key"))
    ));

    let challenges = issuer("https://tit.example/");
    let challenge = challenges
        .issue("alice", &key, ISSUED_AT, LIFETIME)
        .expect("issue a size-limit challenge");
    assert!(matches!(
        challenges.verify(
            &"x".repeat(4 * 1024 + 1),
            "signature",
            "alice",
            &key,
            ISSUED_AT + 1
        ),
        Err(AuthError::InputTooLarge("login challenge"))
    ));
    assert!(matches!(
        challenges.verify(
            &challenge,
            &"x".repeat(16 * 1024 + 1),
            "alice",
            &key,
            ISSUED_AT + 1
        ),
        Err(AuthError::InputTooLarge("SSHSIG envelope"))
    ));

    let bounded = issuer("https://tit.example/");
    for _ in 0..1_024 {
        bounded
            .issue("alice", &key, ISSUED_AT, LIFETIME)
            .expect("fill the active challenge store");
    }
    assert!(matches!(
        bounded.issue("alice", &key, ISSUED_AT, LIFETIME),
        Err(AuthError::NonceLimit)
    ));
    bounded
        .issue("alice", &key, ISSUED_AT + LIFETIME + 1, LIFETIME)
        .expect("prune expired challenges before issuing another one");
}

fn issuer(origin: &str) -> LoginChallenges {
    LoginChallenges::new(&Url::parse(origin).expect("parse the test origin"))
        .expect("create a login challenge issuer")
}

fn parse_public_key(private_key: &Path) -> Result<SshPublicKey, AuthError> {
    let encoded = fs::read_to_string(public_key_path(private_key)).expect("read the public key");
    SshPublicKey::parse(&encoded)
}

fn public_key_path(private_key: &Path) -> PathBuf {
    let mut path = private_key.as_os_str().to_owned();
    path.push(".pub");
    PathBuf::from(path)
}

fn stock_fingerprint(public_key: &Path) -> String {
    let output = Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f"])
        .arg(public_key)
        .output()
        .expect("run ssh-keygen fingerprint");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("read the fingerprint output")
        .split_whitespace()
        .nth(1)
        .expect("find the fingerprint")
        .to_owned()
}

fn sign(
    directory: &TempDir,
    name: &str,
    private_key: &Path,
    namespace: &str,
    message: &str,
) -> String {
    let message_path = directory.path().join(format!("{name}.challenge"));
    fs::write(&message_path, message).expect("write the challenge");
    let output = Command::new("ssh-keygen")
        .args(["-q", "-Y", "sign", "-f"])
        .arg(private_key)
        .args(["-n", namespace])
        .arg(&message_path)
        .output()
        .expect("run ssh-keygen sign");
    assert!(
        output.status.success(),
        "sign the challenge: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut signature_path = message_path.into_os_string();
    signature_path.push(".sig");
    fs::read_to_string(signature_path).expect("read the SSHSIG envelope")
}

#[derive(Clone, Copy)]
enum KeyFixture {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa3072,
}

impl KeyFixture {
    fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 => "ecdsa-p256",
            Self::EcdsaP384 => "ecdsa-p384",
            Self::Rsa2048 => "rsa-2048",
            Self::Rsa3072 => "rsa-3072",
        }
    }
}

fn generate_key(path: &Path, fixture: KeyFixture) {
    let mut command = Command::new("ssh-keygen");
    command.args(["-q", "-N", "", "-C", "test comment", "-f"]);
    command.arg(path);
    match fixture {
        KeyFixture::Ed25519 => {
            command.args(["-t", "ed25519"]);
        }
        KeyFixture::EcdsaP256 => {
            command.args(["-t", "ecdsa", "-b", "256"]);
        }
        KeyFixture::EcdsaP384 => {
            command.args(["-t", "ecdsa", "-b", "384"]);
        }
        KeyFixture::Rsa2048 => {
            command.args(["-t", "rsa", "-b", "2048"]);
        }
        KeyFixture::Rsa3072 => {
            command.args(["-t", "rsa", "-b", "3072"]);
        }
    }
    let output = command.output().expect("run ssh-keygen key generation");
    assert!(
        output.status.success(),
        "generate {}: {}",
        fixture.name(),
        String::from_utf8_lossy(&output.stderr)
    );
}
