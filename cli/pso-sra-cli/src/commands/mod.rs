//! SRA CLI subcommands.

pub mod mint_su;
pub mod register_ar;
pub mod register_sr;

use alloy_primitives::{Address, U256};
use eyre::Result;

/// Parse a hex string into a `U256` (must be exactly 32 bytes).
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

/// Parse a 20-byte hex address (`0x...`).
pub(crate) fn parse_address(s: &str) -> Result<Address> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != 20 {
        eyre::bail!("address hex must be 20 bytes, got {}", bytes.len());
    }
    Ok(Address::from_slice(&bytes))
}

/// Strip an optional `0x` prefix and hex-decode to raw bytes.
pub(crate) fn strip_hex(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
}

/// Parse a comma-separated list of `U256` hex values.
pub(crate) fn parse_uint256_list(s: &str) -> Result<Vec<U256>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split(',').map(|tok| parse_uint256(tok.trim())).collect()
}
