//! SRA CLI subcommands.

pub mod mint_su;
pub mod register_ar;
pub mod register_sr;

use alloy::primitives::{FixedBytes, U256};
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

/// Parse a hex `bytes32` value.
pub(crate) fn parse_b32(s: &str) -> Result<FixedBytes<32>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        eyre::bail!("bytes32 hex must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(FixedBytes::from(arr))
}

/// Parse a comma-separated list of `U256` hex values.
pub(crate) fn parse_uint256_list(s: &str) -> Result<Vec<U256>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split(',').map(|tok| parse_uint256(tok.trim())).collect()
}

/// Parse a comma-separated list of `bytes32` hex values.
pub(crate) fn parse_b32_list(s: &str) -> Result<Vec<FixedBytes<32>>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split(',').map(|tok| parse_b32(tok.trim())).collect()
}

/// Parse a comma-separated list of strings (for SR keys).
pub(crate) fn parse_string_list(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',').map(|tok| tok.trim().to_string()).collect()
}
