use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::auth::{AuthError, SshPublicKey, validate_username};
use crate::instance::{InstanceError, InstanceLock, prepare_database};
use crate::store::{InitialAdministrator, Store, StoreError};

const RECOVERY_PREFIX: &str = "tit-recovery-v1:";

pub(crate) fn setup_administrator(
    instance_dir: &Path,
    username: &str,
    public_key: &str,
) -> Result<String, BootstrapError> {
    validate_username(username)?;
    let public_key = SshPublicKey::parse(public_key)?;
    let _lock = InstanceLock::acquire(instance_dir)?;
    let database = prepare_database(instance_dir)?;
    let mut store = Store::open(&database)?;

    let recovery_code = recovery_code()?;
    let recovery_hash: [u8; 32] = Sha256::digest(recovery_code.as_bytes()).into();
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BootstrapError::Clock)?
        .as_secs()
        .try_into()
        .map_err(|_| BootstrapError::Clock)?;
    store.create_initial_administrator(&InitialAdministrator {
        username,
        canonical_key: public_key.canonical(),
        fingerprint: public_key.fingerprint(),
        recovery_hash: &recovery_hash,
        created_at,
    })?;
    Ok(recovery_code)
}

fn recovery_code() -> Result<String, BootstrapError> {
    let mut bytes = [0_u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| BootstrapError::Random)?;
    let encoded = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("{RECOVERY_PREFIX}{encoded}"))
}

#[derive(Debug, Error)]
pub(crate) enum BootstrapError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Instance(#[from] InstanceError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("cannot create a random recovery code")]
    Random,
    #[error("system clock is before the Unix epoch")]
    Clock,
}
