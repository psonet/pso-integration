//! Wallet CLI subcommands.

pub mod aggregate;
pub mod prepare_su;
pub mod prove_td_full;
pub mod submit_td;

use alloy::primitives::U256;
use eyre::Result;

pub(crate) fn parse_uint256(s: &str) -> Result<U256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        eyre::bail!("uint256 hex must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(arr))
}
