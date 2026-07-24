use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::auth::{AuthError, SshPublicKey, validate_username};
use crate::store::{
    AccountKeyAuthorization, AccountRecovery, InvitedAccount, KeyInspection, NewAuditEvent,
    NewSshKey, PublicProfile, Store, StoreError,
};

const INVITATION_PREFIX: &str = "tit-invite-v1:";
const RECOVERY_PREFIX: &str = "tit-recovery-v1:";
const SECRET_BYTES: usize = 32;
const INVITATION_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
#[allow(
    dead_code,
    reason = "the account integration test imports this module without the Web profile route"
)]
const PROFILE_REPOSITORY_PAGE_SIZE: usize = 20;

#[derive(Clone)]
pub(crate) struct AccountService {
    database: PathBuf,
}

impl AccountService {
    pub(crate) fn new(database: PathBuf) -> Self {
        Self { database }
    }

    pub(crate) fn issue_invitation(&self) -> Result<String, AccountError> {
        let now = now()?;
        let expires_at = now
            .checked_add(INVITATION_LIFETIME_SECONDS)
            .ok_or(AccountError::Clock)?;
        let code = random_secret(INVITATION_PREFIX)?;
        Store::open(&self.database)?.create_signup_invitation(&hash(&code), now, expires_at)?;
        Ok(code)
    }

    pub(crate) fn signup(
        &self,
        invitation: &str,
        username: &str,
        public_key: &str,
        correlation_id: &str,
    ) -> Result<String, AccountError> {
        validate_username(username)?;
        require_secret(invitation, INVITATION_PREFIX)?;
        let key = SshPublicKey::parse(public_key)?;
        let recovery = random_secret(RECOVERY_PREFIX)?;
        let created_at = now()?;
        let mut store = Store::open(&self.database)?;
        let result = store.create_account_with_invitation(&InvitedAccount {
            invitation_hash: &hash(invitation),
            username,
            key: new_key(&key, "initial"),
            recovery_hash: &hash(&recovery),
            created_at,
            correlation_id,
        });
        if let Err(error) = result {
            self.audit_failure(
                "account.signup",
                username,
                username,
                correlation_id,
                created_at,
            )?;
            return Err(error.into());
        }
        Ok(recovery)
    }

    pub(crate) fn recover(
        &self,
        username: &str,
        recovery: &str,
        public_key: &str,
        correlation_id: &str,
    ) -> Result<String, AccountError> {
        validate_username(username)?;
        require_secret(recovery, RECOVERY_PREFIX)?;
        let key = SshPublicKey::parse(public_key)?;
        let replacement = random_secret(RECOVERY_PREFIX)?;
        let created_at = now()?;
        let mut store = Store::open(&self.database)?;
        let result = store.recover_account(&AccountRecovery {
            username,
            old_recovery_hash: &hash(recovery),
            key: new_key(&key, "recovery"),
            new_recovery_hash: &hash(&replacement),
            created_at,
            correlation_id,
        });
        if let Err(error) = result {
            self.audit_failure(
                "account.recover",
                username,
                username,
                correlation_id,
                created_at,
            )?;
            return Err(error.into());
        }
        Ok(replacement)
    }

    pub(crate) fn add_key(
        &self,
        username: &str,
        label: &str,
        public_key: &str,
        actor: &str,
        correlation_id: &str,
    ) -> Result<String, AccountError> {
        validate_username(username)?;
        validate_label(label)?;
        let key = SshPublicKey::parse(public_key)?;
        let created_at = now()?;
        let mut store = Store::open(&self.database)?;
        if let Err(error) = store.add_account_key(
            username,
            &new_key(&key, label),
            created_at,
            actor,
            correlation_id,
        ) {
            let target = format!("{username}:{}", key.fingerprint());
            self.audit_failure("key.add", actor, &target, correlation_id, created_at)?;
            return Err(error.into());
        }
        Ok(key.fingerprint().to_owned())
    }

    pub(crate) fn revoke_key(
        &self,
        username: &str,
        fingerprint: &str,
        actor: &str,
        correlation_id: &str,
    ) -> Result<(), AccountError> {
        validate_username(username)?;
        let changed_at = now()?;
        let mut store = Store::open(&self.database)?;
        if let Err(error) =
            store.revoke_account_key(username, fingerprint, changed_at, actor, correlation_id)
        {
            let target = format!("{username}:{fingerprint}");
            self.audit_failure(
                "key.revoke",
                actor,
                bounded_audit_target(&target),
                correlation_id,
                changed_at,
            )?;
            return Err(error.into());
        }
        Ok(())
    }

    pub(crate) fn suspend(
        &self,
        username: &str,
        suspended: bool,
        actor: &str,
        correlation_id: &str,
    ) -> Result<(), AccountError> {
        validate_username(username)?;
        let changed_at = now()?;
        let mut store = Store::open(&self.database)?;
        let action = if suspended {
            "account.suspend"
        } else {
            "account.resume"
        };
        if let Err(error) =
            store.suspend_account(username, suspended, changed_at, actor, correlation_id)
        {
            self.audit_failure(action, actor, username, correlation_id, changed_at)?;
            return Err(error.into());
        }
        Ok(())
    }

    pub(crate) fn profile(&self, username: &str) -> Result<PublicProfile, AccountError> {
        validate_username(username)?;
        Store::open(&self.database)?
            .public_profile(username)
            .map_err(Into::into)
    }

    #[allow(
        dead_code,
        reason = "the account integration test imports this module without the Web profile route"
    )]
    pub(crate) fn profile_page(
        &self,
        username: &str,
        page: usize,
    ) -> Result<PublicProfile, AccountError> {
        validate_username(username)?;
        if page == 0 || page > 10_000 {
            return Err(AccountError::InvalidProfile);
        }
        let profile = Store::open(&self.database)?
            .public_profile_page(username, page, PROFILE_REPOSITORY_PAGE_SIZE)
            .map_err(AccountError::from)?;
        if page > 1 && profile.repositories.is_empty() {
            return Err(AccountError::InvalidProfile);
        }
        Ok(profile)
    }

    pub(crate) fn update_profile(
        &self,
        username: &str,
        bio: &str,
        contact_email: &str,
    ) -> Result<(), AccountError> {
        validate_username(username)?;
        validate_profile(bio, contact_email)?;
        Store::open(&self.database)?
            .update_profile(username, bio, contact_email)
            .map_err(Into::into)
    }

    #[allow(
        dead_code,
        reason = "the account integration test imports this module without Web account routes"
    )]
    pub(crate) fn keys(&self, username: &str) -> Result<Vec<KeyInspection>, AccountError> {
        validate_username(username)?;
        Ok(Store::open(&self.database)?.inspect_account(username)?.keys)
    }

    #[allow(
        dead_code,
        reason = "the account integration test imports this module without Web account routes"
    )]
    pub(crate) fn complete_key_add(
        &self,
        request: &AccountKeyRequest<'_>,
        label: &str,
        public_key: &str,
    ) -> Result<String, AccountError> {
        let changed_at = now()?;
        let result = (|| {
            validate_username(request.username)?;
            validate_token(request.session)?;
            validate_token(request.csrf)?;
            validate_token(request.secret)?;
            validate_label(label)?;
            let key = SshPublicKey::parse(public_key)?;
            Store::open(&self.database)?.complete_account_key_add(
                &AccountKeyAuthorization {
                    username: request.username,
                    session_hash: &hash(request.session),
                    csrf_hash: &hash(request.csrf),
                    secret_hash: &hash(request.secret),
                    changed_at,
                    correlation_id: request.correlation_id,
                },
                &new_key(&key, label),
            )?;
            Ok(key.fingerprint().to_owned())
        })();
        if result.is_err() {
            self.audit_failure(
                "key.add",
                request.username,
                request.username,
                request.correlation_id,
                changed_at,
            )?;
        }
        result
    }

    #[allow(
        dead_code,
        reason = "the account integration test imports this module without Web account routes"
    )]
    pub(crate) fn complete_key_revoke(
        &self,
        request: &AccountKeyRequest<'_>,
        fingerprint: &str,
    ) -> Result<(), AccountError> {
        let changed_at = now()?;
        let result = (|| {
            validate_username(request.username)?;
            validate_token(request.session)?;
            validate_token(request.csrf)?;
            validate_token(request.secret)?;
            Store::open(&self.database)?.complete_account_key_revoke(
                &AccountKeyAuthorization {
                    username: request.username,
                    session_hash: &hash(request.session),
                    csrf_hash: &hash(request.csrf),
                    secret_hash: &hash(request.secret),
                    changed_at,
                    correlation_id: request.correlation_id,
                },
                fingerprint,
            )?;
            Ok(())
        })();
        if result.is_err() {
            let target = format!("{}:{fingerprint}", request.username);
            self.audit_failure(
                "key.revoke",
                request.username,
                bounded_audit_target(&target),
                request.correlation_id,
                changed_at,
            )?;
        }
        result
    }

    fn audit_failure(
        &self,
        action: &str,
        actor: &str,
        target: &str,
        correlation_id: &str,
        created_at: i64,
    ) -> Result<(), AccountError> {
        Store::open(&self.database)?.record_audit_event(&NewAuditEvent {
            action,
            actor,
            target,
            outcome: "failure",
            correlation_id,
            created_at,
        })?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "integration tests compile accounts without the server"
    )]
    pub(crate) fn database(&self) -> &Path {
        &self.database
    }
}

pub(crate) struct AccountKeyRequest<'a> {
    pub(crate) username: &'a str,
    pub(crate) session: &'a str,
    pub(crate) csrf: &'a str,
    pub(crate) secret: &'a str,
    pub(crate) correlation_id: &'a str,
}

fn new_key<'a>(key: &'a SshPublicKey, label: &'a str) -> NewSshKey<'a> {
    NewSshKey {
        canonical_key: key.canonical(),
        fingerprint: key.fingerprint(),
        label,
    }
}

fn bounded_audit_target(target: &str) -> &str {
    if target.len() <= 512 && !target.chars().any(char::is_control) {
        target
    } else {
        "invalid-target"
    }
}

fn validate_profile(bio: &str, contact_email: &str) -> Result<(), AccountError> {
    if bio.len() > 512
        || bio
            .chars()
            .any(|character| character.is_control() && character != '\n')
    {
        return Err(AccountError::InvalidProfile);
    }
    if contact_email.len() > 254
        || contact_email.chars().any(char::is_control)
        || (!contact_email.is_empty()
            && (contact_email.matches('@').count() != 1
                || contact_email.starts_with('@')
                || contact_email.ends_with('@')))
    {
        return Err(AccountError::InvalidProfile);
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), AccountError> {
    if label.is_empty()
        || label.len() > 80
        || label.trim() != label
        || label.chars().any(char::is_control)
    {
        return Err(AccountError::InvalidLabel);
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "the account integration test imports this module without Web account routes"
)]
fn validate_token(token: &str) -> Result<(), AccountError> {
    if token.len() != SECRET_BYTES * 2 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AccountError::InvalidSecret);
    }
    Ok(())
}

fn require_secret(secret: &str, prefix: &'static str) -> Result<(), AccountError> {
    let encoded = secret
        .strip_prefix(prefix)
        .ok_or(AccountError::InvalidSecret)?;
    if encoded.len() != SECRET_BYTES * 2 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AccountError::InvalidSecret);
    }
    Ok(())
}

fn random_secret(prefix: &'static str) -> Result<String, AccountError> {
    let mut bytes = [0_u8; SECRET_BYTES];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AccountError::Random)?;
    let mut value = String::with_capacity(prefix.len() + SECRET_BYTES * 2);
    value.push_str(prefix);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(value)
}

fn hash(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

fn now() -> Result<i64, AccountError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AccountError::Clock)?
        .as_secs()
        .try_into()
        .map_err(|_| AccountError::Clock)
}

#[derive(Debug, Error)]
pub(crate) enum AccountError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("key label is not valid")]
    InvalidLabel,
    #[error("profile is not valid")]
    InvalidProfile,
    #[error("credential format is not valid")]
    InvalidSecret,
    #[error("cannot create a random credential")]
    Random,
    #[error("system clock is before the Unix epoch")]
    Clock,
}
