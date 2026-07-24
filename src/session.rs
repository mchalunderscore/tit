use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::auth::{
    AuthError, format_keyless_login_challenge, login_origin, verify_keyless_login_challenge,
};
use crate::store::{
    ApproveLogin, NewApprovedWebSession, NewAuditEvent, NewLoginApproval, NewLoginNonce,
    NewWebSession, Store, StoreError, WebSessionRecord,
};

const CHALLENGE_LIFETIME_SECONDS: u64 = 5 * 60;
const SESSION_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
const SECRET_BYTES: usize = 32;

#[derive(Clone)]
pub(crate) struct WebLoginService {
    database: PathBuf,
    origin: String,
}

impl WebLoginService {
    pub(crate) fn new(database: PathBuf, public_url: &Url) -> Result<Self, SessionError> {
        Ok(Self {
            database,
            origin: login_origin(public_url)?,
        })
    }

    pub(crate) fn issue(&self, username: &str) -> Result<IssuedChallenge, SessionError> {
        crate::auth::validate_username(username)?;
        let created_at = now()?;
        let issued_at = u64::try_from(created_at).map_err(|_| SessionError::Clock)?;
        let expires_at = issued_at
            .checked_add(CHALLENGE_LIFETIME_SECONDS)
            .ok_or(SessionError::Clock)?;
        let nonce = random_bytes()?;
        let login_csrf = encode_hex(&random_bytes()?);
        Store::open(&self.database)?.create_login_nonce(&NewLoginNonce {
            nonce_hash: &hash(&nonce),
            csrf_hash: &hash(login_csrf.as_bytes()),
            username,
            created_at,
            expires_at: i64::try_from(expires_at).map_err(|_| SessionError::Clock)?,
        })?;
        Ok(IssuedChallenge {
            challenge: format_keyless_login_challenge(
                &self.origin,
                username,
                &nonce,
                issued_at,
                expires_at,
            ),
            login_csrf,
        })
    }

    pub(crate) fn issue_approval(&self) -> Result<IssuedLoginApproval, SessionError> {
        let created_at = now()?;
        let expires_at = created_at
            .checked_add(
                i64::try_from(CHALLENGE_LIFETIME_SECONDS).map_err(|_| SessionError::Clock)?,
            )
            .ok_or(SessionError::Clock)?;
        let secret = encode_hex(&random_bytes()?);
        let login_csrf = encode_hex(&random_bytes()?);
        Store::open(&self.database)?.create_login_approval(&NewLoginApproval {
            secret_hash: &hash(secret.as_bytes()),
            csrf_hash: &hash(login_csrf.as_bytes()),
            purpose: "login",
            expected_username: None,
            created_at,
            expires_at,
        })?;
        Ok(IssuedLoginApproval { secret, login_csrf })
    }

    #[allow(
        dead_code,
        reason = "the Web session integration test imports this module without account routes"
    )]
    pub(crate) fn issue_account_approval(
        &self,
        username: &str,
        csrf: &str,
    ) -> Result<IssuedLoginApproval, SessionError> {
        crate::auth::validate_username(username)?;
        validate_token(csrf)?;
        let created_at = now()?;
        let expires_at = created_at
            .checked_add(
                i64::try_from(CHALLENGE_LIFETIME_SECONDS).map_err(|_| SessionError::Clock)?,
            )
            .ok_or(SessionError::Clock)?;
        let secret = encode_hex(&random_bytes()?);
        Store::open(&self.database)?.create_login_approval(&NewLoginApproval {
            secret_hash: &hash(secret.as_bytes()),
            csrf_hash: &hash(csrf.as_bytes()),
            purpose: "account-key",
            expected_username: Some(username),
            created_at,
            expires_at,
        })?;
        Ok(IssuedLoginApproval {
            secret,
            login_csrf: csrf.to_owned(),
        })
    }

    pub(crate) fn approve(
        &self,
        secret: &str,
        username: &str,
        fingerprint: &str,
    ) -> Result<ApprovedLogin, SessionError> {
        validate_token(secret)?;
        Store::open(&self.database)?.approve_login(&ApproveLogin {
            secret_hash: &hash(secret.as_bytes()),
            username,
            fingerprint,
            approved_at: now()?,
        })?;
        Ok(ApprovedLogin {
            origin: self.origin.clone(),
            username: username.to_owned(),
        })
    }

    pub(crate) fn complete_approval(
        &self,
        secret: &str,
        login_csrf: &str,
        correlation_id: &str,
    ) -> Result<NewSession, SessionError> {
        validate_token(secret)?;
        validate_token(login_csrf)?;
        let created_at = now()?;
        let session = encode_hex(&random_bytes()?);
        let csrf = encode_hex(&random_bytes()?);
        let expires_at = created_at
            .checked_add(SESSION_LIFETIME_SECONDS)
            .ok_or(SessionError::Clock)?;
        Store::open(&self.database)?.consume_login_approval(&NewApprovedWebSession {
            secret_hash: &hash(secret.as_bytes()),
            login_csrf_hash: &hash(login_csrf.as_bytes()),
            session_hash: &hash(session.as_bytes()),
            csrf_hash: &hash(csrf.as_bytes()),
            created_at,
            expires_at,
            correlation_id,
        })?;
        Ok(NewSession {
            token: session,
            csrf,
        })
    }

    pub(crate) fn verify(
        &self,
        username: &str,
        challenge: &str,
        signature: &str,
        login_csrf: &str,
        correlation_id: &str,
    ) -> Result<NewSession, SessionError> {
        let created_at = now()?;
        let result = (|| {
            validate_token(login_csrf)?;
            let verified = verify_keyless_login_challenge(
                &self.origin,
                challenge,
                signature,
                username,
                u64::try_from(created_at).map_err(|_| SessionError::Clock)?,
            )?;
            let session = encode_hex(&random_bytes()?);
            let csrf = encode_hex(&random_bytes()?);
            let expires_at = created_at
                .checked_add(SESSION_LIFETIME_SECONDS)
                .ok_or(SessionError::Clock)?;
            Store::open(&self.database)?.consume_login_nonce(&NewWebSession {
                nonce_hash: &verified.nonce_hash,
                login_csrf_hash: &hash(login_csrf.as_bytes()),
                username: &verified.username,
                fingerprint: &verified.fingerprint,
                session_hash: &hash(session.as_bytes()),
                csrf_hash: &hash(csrf.as_bytes()),
                created_at,
                expires_at,
                correlation_id,
            })?;
            Ok(NewSession {
                token: session,
                csrf,
            })
        })();
        if result.is_err() {
            let account = audit_account(username);
            Store::open(&self.database)?.record_audit_event(&NewAuditEvent {
                action: "login",
                actor: account,
                target: account,
                outcome: "failure",
                correlation_id,
                created_at,
            })?;
        }
        result
    }

    pub(crate) fn authenticate(
        &self,
        session: &str,
        csrf: Option<&str>,
    ) -> Result<WebSessionRecord, SessionError> {
        validate_token(session)?;
        if let Some(csrf) = csrf {
            validate_token(csrf)?;
        }
        Store::open(&self.database)?
            .web_session(
                &hash(session.as_bytes()),
                csrf.map(|value| hash(value.as_bytes())).as_ref(),
                now()?,
            )
            .map_err(Into::into)
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile login without HTTP handlers"
    )]
    pub(crate) fn record_login_failure(
        &self,
        username: &str,
        correlation_id: &str,
    ) -> Result<(), SessionError> {
        let account = audit_account(username);
        Store::open(&self.database)?.record_audit_event(&NewAuditEvent {
            action: "login",
            actor: account,
            target: account,
            outcome: "failure",
            correlation_id,
            created_at: now()?,
        })?;
        Ok(())
    }

    pub(crate) fn end_all(&self, username: &str) -> Result<(), SessionError> {
        Store::open(&self.database)?.end_account_sessions(username, now()?)?;
        Ok(())
    }
}

fn audit_account(username: &str) -> &str {
    if !username.is_empty() && username.len() <= 40 && username.is_ascii() {
        username
    } else {
        "invalid-account"
    }
}

pub(crate) struct IssuedChallenge {
    pub(crate) challenge: String,
    pub(crate) login_csrf: String,
}

pub(crate) struct IssuedLoginApproval {
    pub(crate) secret: String,
    pub(crate) login_csrf: String,
}

pub(crate) struct ApprovedLogin {
    pub(crate) origin: String,
    pub(crate) username: String,
}

pub(crate) struct NewSession {
    pub(crate) token: String,
    pub(crate) csrf: String,
}

fn random_bytes() -> Result<[u8; SECRET_BYTES], SessionError> {
    let mut bytes = [0_u8; SECRET_BYTES];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| SessionError::Random)?;
    Ok(bytes)
}

fn hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn encode_hex(value: &[u8]) -> String {
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        use std::fmt::Write as _;
        write!(result, "{byte:02x}").expect("writing to a string cannot fail");
    }
    result
}

fn validate_token(token: &str) -> Result<(), SessionError> {
    if token.len() != SECRET_BYTES * 2 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SessionError::InvalidToken);
    }
    Ok(())
}

fn now() -> Result<i64, SessionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SessionError::Clock)?
        .as_secs()
        .try_into()
        .map_err(|_| SessionError::Clock)
}

#[derive(Debug, Error)]
pub(crate) enum SessionError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("session token is not valid")]
    InvalidToken,
    #[error("cannot create random session data")]
    Random,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[allow(dead_code, reason = "integration tests use the service without HTTP")]
    #[error("Web login service is not available")]
    Unavailable,
}
