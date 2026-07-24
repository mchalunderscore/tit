#![allow(
    dead_code,
    reason = "integration test crates use only the system operations required by their imported modules"
)]

use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRng;

use crate::codec::encode_lower_hex;

pub(crate) fn random_lower_hex<const N: usize>() -> Option<String> {
    let mut bytes = [0_u8; N];
    rand::rngs::SysRng.try_fill_bytes(&mut bytes).ok()?;
    Some(encode_lower_hex(&bytes))
}

pub(crate) fn unix_timestamp() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .try_into()
        .ok()
}
