use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PublicKey, SshSig};
use thiserror::Error;

use crate::codec::{decode_lower_hex, encode_lower_hex};
use url::Url;

const KEYLESS_CHALLENGE_HEADER: &str = "tit-auth-v2";
const CHALLENGE_PURPOSE: &str = "web-login";
const SIGNATURE_NAMESPACE: &str = "tit-auth";
const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_CHALLENGE_BYTES: usize = 4 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_CHALLENGE_LIFETIME_SECONDS: u64 = 5 * 60;
const NONCE_BYTES: usize = 32;
const MINIMUM_RSA_BITS: u32 = 3_072;

#[derive(Clone, Debug)]
pub(crate) struct SshPublicKey {
    key: PublicKey,
    canonical: String,
    fingerprint: String,
}

impl SshPublicKey {
    pub(crate) fn parse(input: &str) -> Result<Self, AuthError> {
        if input.len() > MAX_KEY_BYTES {
            return Err(AuthError::InputTooLarge("SSH public key"));
        }

        let key = PublicKey::from_openssh(input).map_err(AuthError::PublicKey)?;
        Self::from_public_key(key)
    }

    fn from_public_key(mut key: PublicKey) -> Result<Self, AuthError> {
        validate_key_algorithm(&key)?;
        key.set_comment("");
        let canonical = key.to_openssh().map_err(AuthError::PublicKey)?;
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        Ok(Self {
            key,
            canonical,
            fingerprint,
        })
    }

    pub(crate) fn canonical(&self) -> &str {
        &self.canonical
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.key
    }
}

pub(crate) fn format_keyless_login_challenge(
    origin: &str,
    username: &str,
    nonce: &[u8; NONCE_BYTES],
    issued_at: u64,
    expires_at: u64,
) -> String {
    format!(
        "{KEYLESS_CHALLENGE_HEADER}\npurpose={CHALLENGE_PURPOSE}\norigin={origin}\nusername={username}\nnonce={}\nissued-at={issued_at}\nexpires-at={expires_at}\n",
        encode_lower_hex(nonce)
    )
}

pub(crate) fn verify_keyless_login_challenge(
    origin: &str,
    challenge: &str,
    signature: &str,
    expected_username: &str,
    now: u64,
) -> Result<PersistentVerifiedLogin, AuthError> {
    if challenge.len() > MAX_CHALLENGE_BYTES {
        return Err(AuthError::InputTooLarge("login challenge"));
    }
    if signature.len() > MAX_SIGNATURE_BYTES {
        return Err(AuthError::InputTooLarge("SSHSIG envelope"));
    }
    validate_username(expected_username)?;
    let fields = KeylessChallengeFields::parse(challenge)?;
    if fields.origin != origin {
        return Err(AuthError::WrongOrigin);
    }
    if fields.username != expected_username {
        return Err(AuthError::WrongUsername);
    }
    if fields.expires_at <= fields.issued_at
        || fields.expires_at - fields.issued_at > MAX_CHALLENGE_LIFETIME_SECONDS
    {
        return Err(AuthError::InvalidLifetime);
    }
    if now < fields.issued_at || now > fields.expires_at {
        return Err(AuthError::ExpiredChallenge);
    }
    let sshsig = SshSig::from_pem(signature).map_err(AuthError::SignatureEnvelope)?;
    let key = SshPublicKey::from_public_key(PublicKey::new(sshsig.public_key().clone(), ""))?;
    validate_signature_algorithm(key.public_key(), &sshsig)?;
    key.public_key()
        .verify(SIGNATURE_NAMESPACE, challenge.as_bytes(), &sshsig)
        .map_err(AuthError::SignatureVerification)?;
    Ok(PersistentVerifiedLogin {
        username: fields.username.to_owned(),
        fingerprint: key.fingerprint().to_owned(),
        nonce_hash: hash_nonce(&fields.nonce),
    })
}

pub(crate) fn login_origin(public_url: &Url) -> Result<String, AuthError> {
    if !matches!(public_url.scheme(), "http" | "https")
        || public_url.host().is_none()
        || !public_url.username().is_empty()
        || public_url.password().is_some()
        || public_url.query().is_some()
        || public_url.fragment().is_some()
        || public_url.path() != "/"
    {
        return Err(AuthError::InvalidOrigin);
    }
    Ok(public_url.origin().ascii_serialization())
}

pub(crate) struct PersistentVerifiedLogin {
    pub(crate) username: String,
    pub(crate) fingerprint: String,
    pub(crate) nonce_hash: [u8; 32],
}

#[derive(Debug, Error)]
pub(crate) enum AuthError {
    #[error("{0} is too large")]
    InputTooLarge(&'static str),
    #[error("SSH public key is not valid: {0}")]
    PublicKey(ssh_key::Error),
    #[error("SSH public key algorithm is not supported")]
    UnsupportedKeyAlgorithm,
    #[error("RSA key has {actual} bits, but a minimum of {minimum} bits is necessary")]
    UndersizedRsa { actual: u32, minimum: u32 },
    #[error("username is not valid")]
    InvalidUsername,
    #[error("canonical origin is not valid")]
    InvalidOrigin,
    #[error("challenge lifetime is not valid")]
    InvalidLifetime,
    #[error("login challenge is not valid")]
    MalformedChallenge,
    #[error("login challenge has the wrong origin")]
    WrongOrigin,
    #[error("login challenge has the wrong username")]
    WrongUsername,
    #[error("login challenge has expired or is not active")]
    ExpiredChallenge,
    #[error("SSHSIG envelope is not valid: {0}")]
    SignatureEnvelope(ssh_key::Error),
    #[error("SSHSIG algorithm is not supported")]
    UnsupportedSignatureAlgorithm,
    #[error("SSHSIG verification failed: {0}")]
    SignatureVerification(ssh_key::Error),
}

struct KeylessChallengeFields<'a> {
    origin: &'a str,
    username: &'a str,
    nonce: [u8; NONCE_BYTES],
    issued_at: u64,
    expires_at: u64,
}

impl<'a> KeylessChallengeFields<'a> {
    fn parse(challenge: &'a str) -> Result<Self, AuthError> {
        let body = challenge
            .strip_suffix('\n')
            .ok_or(AuthError::MalformedChallenge)?;
        let mut lines = body.split('\n');
        if lines.next() != Some(KEYLESS_CHALLENGE_HEADER)
            || lines.next() != Some("purpose=web-login")
        {
            return Err(AuthError::MalformedChallenge);
        }
        let origin = field(lines.next(), "origin=")?;
        let username = field(lines.next(), "username=")?;
        validate_username(username)?;
        let nonce = decode_hex(field(lines.next(), "nonce=")?)?;
        let issued_at = parse_time(field(lines.next(), "issued-at=")?)?;
        let expires_at = parse_time(field(lines.next(), "expires-at=")?)?;
        if lines.next().is_some() || origin.is_empty() || origin.contains(['\r', '\n']) {
            return Err(AuthError::MalformedChallenge);
        }
        Ok(Self {
            origin,
            username,
            nonce,
            issued_at,
            expires_at,
        })
    }
}

fn validate_key_algorithm(key: &PublicKey) -> Result<(), AuthError> {
    match key.key_data() {
        ssh_key::public::KeyData::Ed25519(_) => Ok(()),
        ssh_key::public::KeyData::Ecdsa(key) if key.curve() == EcdsaCurve::NistP256 => Ok(()),
        ssh_key::public::KeyData::Rsa(key) if key.key_size() < MINIMUM_RSA_BITS => {
            Err(AuthError::UndersizedRsa {
                actual: key.key_size(),
                minimum: MINIMUM_RSA_BITS,
            })
        }
        _ => Err(AuthError::UnsupportedKeyAlgorithm),
    }
}

fn validate_signature_algorithm(key: &PublicKey, signature: &SshSig) -> Result<(), AuthError> {
    let valid = match (key.key_data(), signature.algorithm()) {
        (ssh_key::public::KeyData::Ed25519(_), Algorithm::Ed25519) => true,
        (ssh_key::public::KeyData::Ecdsa(key), Algorithm::Ecdsa { curve }) => {
            key.curve() == EcdsaCurve::NistP256 && curve == EcdsaCurve::NistP256
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(AuthError::UnsupportedSignatureAlgorithm)
    }
}

pub(crate) fn validate_username(username: &str) -> Result<(), AuthError> {
    let bytes = username.as_bytes();
    let valid_character = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if !(1..=40).contains(&bytes.len())
        || !valid_character(bytes[0])
        || !valid_character(bytes[bytes.len() - 1])
        || !bytes
            .iter()
            .all(|byte| valid_character(*byte) || *byte == b'-')
        || matches!(
            username,
            "admin" | "api" | "assets" | "feeds" | "issues" | "setup"
        )
    {
        return Err(AuthError::InvalidUsername);
    }
    Ok(())
}

fn field<'a>(line: Option<&'a str>, prefix: &str) -> Result<&'a str, AuthError> {
    line.and_then(|line| line.strip_prefix(prefix))
        .ok_or(AuthError::MalformedChallenge)
}

fn parse_time(value: &str) -> Result<u64, AuthError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(AuthError::MalformedChallenge);
    }
    value
        .parse::<u64>()
        .map_err(|_| AuthError::MalformedChallenge)
}

fn hash_nonce(nonce: &[u8; NONCE_BYTES]) -> [u8; 32] {
    Sha256::digest(nonce).into()
}

fn decode_hex(value: &str) -> Result<[u8; NONCE_BYTES], AuthError> {
    let decoded = decode_lower_hex(value.as_bytes()).ok_or(AuthError::MalformedChallenge)?;
    let decoded: [u8; NONCE_BYTES] = decoded
        .try_into()
        .map_err(|_| AuthError::MalformedChallenge)?;
    Ok(decoded)
}
