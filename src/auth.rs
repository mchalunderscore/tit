use std::collections::HashMap;
use std::sync::Mutex;

use rand::TryRng;
use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PublicKey, SshSig};
use thiserror::Error;
use url::Url;

const CHALLENGE_HEADER: &str = "tit-auth-v1";
const CHALLENGE_PURPOSE: &str = "web-login";
const SIGNATURE_NAMESPACE: &str = "tit-auth";
const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_CHALLENGE_BYTES: usize = 4 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_CHALLENGE_LIFETIME_SECONDS: u64 = 5 * 60;
const MAX_OUTSTANDING_CHALLENGES: usize = 1_024;
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

        let mut key = PublicKey::from_openssh(input).map_err(AuthError::PublicKey)?;
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

#[derive(Debug)]
pub(crate) struct LoginChallenges {
    origin: String,
    nonces: Mutex<HashMap<[u8; 32], u64>>,
}

impl LoginChallenges {
    pub(crate) fn new(public_url: &Url) -> Result<Self, AuthError> {
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

        Ok(Self {
            origin: public_url.origin().ascii_serialization(),
            nonces: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn issue(
        &self,
        username: &str,
        key: &SshPublicKey,
        issued_at: u64,
        lifetime_seconds: u64,
    ) -> Result<String, AuthError> {
        validate_username(username)?;
        if lifetime_seconds == 0 || lifetime_seconds > MAX_CHALLENGE_LIFETIME_SECONDS {
            return Err(AuthError::InvalidLifetime);
        }
        let expires_at = issued_at
            .checked_add(lifetime_seconds)
            .ok_or(AuthError::InvalidLifetime)?;

        let nonce = self.new_nonce(issued_at, expires_at)?;
        Ok(format!(
            "{CHALLENGE_HEADER}\npurpose={CHALLENGE_PURPOSE}\norigin={}\nusername={username}\nfingerprint={}\nnonce={}\nissued-at={issued_at}\nexpires-at={expires_at}\n",
            self.origin,
            key.fingerprint(),
            encode_hex(&nonce)
        ))
    }

    pub(crate) fn verify(
        &self,
        challenge: &str,
        signature: &str,
        expected_username: &str,
        expected_key: &SshPublicKey,
        now: u64,
    ) -> Result<VerifiedLogin, AuthError> {
        if challenge.len() > MAX_CHALLENGE_BYTES {
            return Err(AuthError::InputTooLarge("login challenge"));
        }
        if signature.len() > MAX_SIGNATURE_BYTES {
            return Err(AuthError::InputTooLarge("SSHSIG envelope"));
        }
        validate_username(expected_username)?;

        let fields = ChallengeFields::parse(challenge)?;
        if fields.origin != self.origin {
            return Err(AuthError::WrongOrigin);
        }
        if fields.username != expected_username {
            return Err(AuthError::WrongUsername);
        }
        if fields.fingerprint != expected_key.fingerprint() {
            return Err(AuthError::WrongKey);
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
        validate_signature_algorithm(expected_key.public_key(), &sshsig)?;
        expected_key
            .public_key()
            .verify(SIGNATURE_NAMESPACE, challenge.as_bytes(), &sshsig)
            .map_err(AuthError::SignatureVerification)?;

        let nonce_hash = hash_nonce(&fields.nonce);
        let mut nonces = self.nonces.lock().map_err(|_| AuthError::NonceStore)?;
        match nonces.get(&nonce_hash) {
            Some(stored_expiry) if *stored_expiry == fields.expires_at => {
                nonces.remove(&nonce_hash);
            }
            _ => return Err(AuthError::ConsumedChallenge),
        }

        Ok(VerifiedLogin {
            username: fields.username.to_owned(),
            fingerprint: fields.fingerprint.to_owned(),
        })
    }

    fn new_nonce(&self, issued_at: u64, expires_at: u64) -> Result<[u8; NONCE_BYTES], AuthError> {
        loop {
            let mut nonce = [0_u8; NONCE_BYTES];
            rand::rngs::SysRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| AuthError::Random)?;
            let hash = hash_nonce(&nonce);
            let mut nonces = self.nonces.lock().map_err(|_| AuthError::NonceStore)?;
            nonces.retain(|_, stored_expiry| *stored_expiry >= issued_at);
            if nonces.len() >= MAX_OUTSTANDING_CHALLENGES {
                return Err(AuthError::NonceLimit);
            }
            if let std::collections::hash_map::Entry::Vacant(entry) = nonces.entry(hash) {
                entry.insert(expires_at);
                return Ok(nonce);
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VerifiedLogin {
    pub(crate) username: String,
    pub(crate) fingerprint: String,
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
    #[error("cannot get random bytes")]
    Random,
    #[error("login challenge is not valid")]
    MalformedChallenge,
    #[error("login challenge has the wrong origin")]
    WrongOrigin,
    #[error("login challenge has the wrong username")]
    WrongUsername,
    #[error("login challenge has the wrong SSH key")]
    WrongKey,
    #[error("login challenge has expired or is not active")]
    ExpiredChallenge,
    #[error("SSHSIG envelope is not valid: {0}")]
    SignatureEnvelope(ssh_key::Error),
    #[error("SSHSIG algorithm is not supported")]
    UnsupportedSignatureAlgorithm,
    #[error("SSHSIG verification failed: {0}")]
    SignatureVerification(ssh_key::Error),
    #[error("login challenge was consumed or was not issued")]
    ConsumedChallenge,
    #[error("login nonce store is not available")]
    NonceStore,
    #[error("too many login challenges are active")]
    NonceLimit,
}

struct ChallengeFields<'a> {
    origin: &'a str,
    username: &'a str,
    fingerprint: &'a str,
    nonce: [u8; NONCE_BYTES],
    issued_at: u64,
    expires_at: u64,
}

impl<'a> ChallengeFields<'a> {
    fn parse(challenge: &'a str) -> Result<Self, AuthError> {
        let body = challenge
            .strip_suffix('\n')
            .ok_or(AuthError::MalformedChallenge)?;
        let mut lines = body.split('\n');
        if lines.next() != Some(CHALLENGE_HEADER) || lines.next() != Some("purpose=web-login") {
            return Err(AuthError::MalformedChallenge);
        }
        let origin = field(lines.next(), "origin=")?;
        let username = field(lines.next(), "username=")?;
        validate_username(username)?;
        let fingerprint = field(lines.next(), "fingerprint=")?;
        let nonce = decode_hex(field(lines.next(), "nonce=")?)?;
        let issued_at = parse_time(field(lines.next(), "issued-at=")?)?;
        let expires_at = parse_time(field(lines.next(), "expires-at=")?)?;
        if lines.next().is_some()
            || origin.is_empty()
            || fingerprint.is_empty()
            || origin.contains(['\r', '\n'])
            || fingerprint.contains(['\r', '\n'])
        {
            return Err(AuthError::MalformedChallenge);
        }
        Ok(Self {
            origin,
            username,
            fingerprint,
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

fn validate_username(username: &str) -> Result<(), AuthError> {
    let bytes = username.as_bytes();
    let valid_character = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if !(1..=40).contains(&bytes.len())
        || !valid_character(bytes[0])
        || !valid_character(bytes[bytes.len() - 1])
        || !bytes
            .iter()
            .all(|byte| valid_character(*byte) || *byte == b'-')
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

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(value: &str) -> Result<[u8; NONCE_BYTES], AuthError> {
    if value.len() != NONCE_BYTES * 2 {
        return Err(AuthError::MalformedChallenge);
    }
    let mut bytes = [0_u8; NONCE_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_hex_digit(pair[0])? << 4) | decode_hex_digit(pair[1])?;
    }
    Ok(bytes)
}

fn decode_hex_digit(value: u8) -> Result<u8, AuthError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthError::MalformedChallenge),
    }
}
