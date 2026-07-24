use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::auth::{AuthError, validate_username};
use crate::store::{
    ActivityCursor, ActivityPage, FeedTokenRecord, Store, StoreError, TokenFeedPage,
};

const TOKEN_BYTES: usize = 32;

#[derive(Clone)]
pub(crate) struct FeedTokenService {
    database: PathBuf,
}

impl FeedTokenService {
    pub(crate) fn new(database: &Path) -> Self {
        Self {
            database: database.to_owned(),
        }
    }

    pub(crate) fn list(&self, actor: &str) -> Result<Vec<FeedTokenRecord>, FeedTokenError> {
        validate_username(actor)?;
        Store::open(&self.database)?
            .feed_tokens(actor)
            .map_err(Into::into)
    }

    pub(crate) fn issue(&self, actor: &str) -> Result<IssuedFeedToken, FeedTokenError> {
        validate_username(actor)?;
        let token = random_token()?;
        let record =
            Store::open(&self.database)?.create_feed_token(actor, &hash(&token), now()?)?;
        Ok(IssuedFeedToken { record, token })
    }

    pub(crate) fn rotate(&self, actor: &str, id: &str) -> Result<IssuedFeedToken, FeedTokenError> {
        validate_username(actor)?;
        validate_id(id)?;
        let token = random_token()?;
        let record =
            Store::open(&self.database)?.rotate_feed_token(actor, id, &hash(&token), now()?)?;
        Ok(IssuedFeedToken { record, token })
    }

    pub(crate) fn revoke(&self, actor: &str, id: &str) -> Result<(), FeedTokenError> {
        validate_username(actor)?;
        validate_id(id)?;
        Store::open(&self.database)?
            .revoke_feed_token(actor, id, now()?)
            .map_err(Into::into)
    }

    pub(crate) fn read(&self, token: &str, limit: usize) -> Result<TokenFeedPage, FeedTokenError> {
        validate_token(token)?;
        Store::open(&self.database)?
            .token_feed_events(&hash(token), limit)
            .map_err(Into::into)
    }

    pub(crate) fn activity(
        &self,
        actor: &str,
        before: Option<&ActivityCursor>,
        limit: usize,
    ) -> Result<ActivityPage, FeedTokenError> {
        validate_username(actor)?;
        Store::open(&self.database)?
            .watched_activity_page(actor, before, limit)
            .map_err(Into::into)
    }
}

pub(crate) struct IssuedFeedToken {
    pub(crate) record: FeedTokenRecord,
    pub(crate) token: String,
}

fn random_token() -> Result<String, FeedTokenError> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| FeedTokenError::Random)?;
    Ok(encode_hex(&bytes))
}

fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn validate_token(token: &str) -> Result<(), FeedTokenError> {
    if token.len() != TOKEN_BYTES * 2 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(FeedTokenError::InvalidToken);
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<(), FeedTokenError> {
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(FeedTokenError::InvalidToken);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

fn now() -> Result<i64, FeedTokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FeedTokenError::Clock)?
        .as_secs()
        .try_into()
        .map_err(|_| FeedTokenError::Clock)
}

#[derive(Debug, Error)]
pub(crate) enum FeedTokenError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("feed token is not valid")]
    InvalidToken,
    #[error("cannot create random feed token data")]
    Random,
    #[error("system clock is before the Unix epoch")]
    Clock,
}
