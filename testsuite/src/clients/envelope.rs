//! PSO Users-pool envelope encoder.
//!
//! Mirrors the layout in `pso-chain/crates/pso-chain/src/pool/calldata.rs`:
//!
//! ```text
//! [4B magic = 0xCAFED00D] [32B nullifier] [32B vdf_input]
//! [48B vdf_output] [48B vdf_proof] [8B submitted_block]
//! [inner EVM calldata...]
//! ```
//!
//! The chain re-derives `vdf_input` as
//! `SHA-256(signer || tx_nonce_le || submitted_block_le || chain_id_le)`
//! and validates the MinRoot proof against the current (or previous)
//! epoch's `T`. Wallets MUST use the exact same byte order or the
//! validator rejects with `BadVdfInputBinding` before even running
//! the VDF verify.
//!
//! We compute the VDF here synchronously — at `T_BASE = 100` (the
//! pso-chain `--dev` setting) the cost is sub-millisecond on a
//! desktop CPU. The helper takes the difficulty as an argument so
//! callers who already polled `pso_vdfInfo` don't pay for it
//! twice.

use alloy::primitives::Address;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use pso_vdf::minroot::MinRootVdf;
use pso_vdf::types::VdfInput;
use pso_vdf::Vdf;

/// Default PSO magic prefix. **Mirrors**
/// `pso-chain/crates/pso-chain/src/pool/calldata.rs::DEFAULT_PSO_MAGIC`.
/// If pso-chain rotates the magic we MUST update this constant
/// together with the chain side — there is no shared dep.
pub const DEFAULT_PSO_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xD0, 0x0D];

/// Env var matching the chain's `PSO_MAGIC_PREFIX` setting. Accepts
/// 8 hex digits with or without `0x`; invalid values fall back to
/// [`DEFAULT_PSO_MAGIC`] (mirrors the chain's lenient behaviour).
pub const PSO_MAGIC_PREFIX_ENV: &str = "PSO_MAGIC_PREFIX";

/// Resolve the active magic prefix, taking `PSO_MAGIC_PREFIX` into
/// account. Re-read on every call — tests routinely flip it via
/// `std::env::set_var` and rebuild a single envelope.
pub fn pso_magic() -> [u8; 4] {
    match std::env::var(PSO_MAGIC_PREFIX_ENV) {
        Err(_) => DEFAULT_PSO_MAGIC,
        Ok(s) => {
            let stripped = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(&s);
            if stripped.len() != 8 {
                return DEFAULT_PSO_MAGIC;
            }
            match hex::decode(stripped) {
                Ok(bytes) if bytes.len() == 4 => {
                    let mut out = [0u8; 4];
                    out.copy_from_slice(&bytes);
                    out
                }
                _ => DEFAULT_PSO_MAGIC,
            }
        }
    }
}

/// Fixed header size (4 + 32 + 32 + 48 + 48 + 8 = 172 bytes). Same
/// constant as pso-chain's `PSO_MIN_HEADER`.
pub const PSO_MIN_HEADER: usize = 172;

/// Canonical VDF input construction.
///
/// `vdf_input = SHA-256(signer_be_20 || tx_nonce_le_8 || submitted_block_le_8 || chain_id_le_8)`.
///
/// Duplicates `pso_vdf::params::VdfParams::derive_input_from`; we
/// inline it so a test build doesn't have to depend on `pso-vdf`'s
/// no-std-leaning helper module just for one SHA-256.
pub fn derive_vdf_input(
    signer: Address,
    tx_nonce: u64,
    submitted_block: u64,
    chain_id: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(signer.0 .0);
    hasher.update(tx_nonce.to_le_bytes());
    hasher.update(submitted_block.to_le_bytes());
    hasher.update(chain_id.to_le_bytes());
    hasher.finalize().into()
}

/// Wrap `inner_calldata` in the PSO Users-pool envelope.
///
/// Steps:
/// 1. Roll a fresh 32-byte random nullifier (replay protection;
///    chain rejects duplicates).
/// 2. Derive `vdf_input` per the canonical binding.
/// 3. Run MinRoot at `difficulty` iterations (the caller's job to
///    fetch the right value from `pso_vdfInfo`).
/// 4. Concatenate the 172-byte header with the inner EVM calldata.
///
/// Returns the encoded bytes ready to be set as the `data` field of
/// an EIP-1559 transaction.
pub fn build_users_pool_calldata(
    signer: Address,
    tx_nonce: u64,
    submitted_block: u64,
    chain_id: u64,
    difficulty: u64,
    inner_calldata: &[u8],
) -> eyre::Result<Vec<u8>> {
    if difficulty == 0 {
        return Err(eyre::eyre!("VDF difficulty must be > 0"));
    }

    let mut nullifier = [0u8; 32];
    OsRng.fill_bytes(&mut nullifier);

    let vdf_input_bytes = derive_vdf_input(signer, tx_nonce, submitted_block, chain_id);
    let vdf_input = VdfInput::from_bytes(vdf_input_bytes);
    let (vdf_output, vdf_proof) = MinRootVdf::eval(&vdf_input, difficulty);

    let mut out = Vec::with_capacity(PSO_MIN_HEADER + inner_calldata.len());
    out.extend_from_slice(&pso_magic());
    out.extend_from_slice(&nullifier);
    out.extend_from_slice(&vdf_input_bytes);
    // VdfOutput is `Vec<u8>` (48 bytes for MinRoot/BLS12-381).
    debug_assert_eq!(vdf_output.0.len(), 48, "VdfOutput is 48 bytes");
    out.extend_from_slice(&vdf_output.0);
    debug_assert_eq!(vdf_proof.inner.len(), 48, "VdfProof is 48 bytes");
    out.extend_from_slice(&vdf_proof.inner);
    out.extend_from_slice(&submitted_block.to_be_bytes());
    out.extend_from_slice(inner_calldata);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_has_correct_header_size() {
        let signer = Address::from([0xab; 20]);
        let inner = vec![0u8; 64];
        let env = build_users_pool_calldata(signer, 0, 1, 1, 16, &inner).unwrap();
        assert!(env.len() >= PSO_MIN_HEADER);
        assert_eq!(env.len(), PSO_MIN_HEADER + inner.len());
        assert_eq!(&env[..4], &pso_magic());
        assert_eq!(&env[PSO_MIN_HEADER..], &inner[..]);
    }

    #[test]
    fn vdf_input_matches_canonical_binding() {
        let signer = Address::from([0xcd; 20]);
        let a = derive_vdf_input(signer, 7, 100, 19_280_501);
        let b = derive_vdf_input(signer, 7, 100, 19_280_501);
        assert_eq!(a, b);
        let c = derive_vdf_input(signer, 8, 100, 19_280_501);
        assert_ne!(a, c);
    }

    #[test]
    fn magic_env_override_round_trip() {
        // Save and restore to keep test ordering benign.
        let saved = std::env::var(PSO_MAGIC_PREFIX_ENV).ok();
        std::env::set_var(PSO_MAGIC_PREFIX_ENV, "0xDEADBEEF");
        assert_eq!(pso_magic(), [0xDE, 0xAD, 0xBE, 0xEF]);
        std::env::set_var(PSO_MAGIC_PREFIX_ENV, "bogus");
        assert_eq!(pso_magic(), DEFAULT_PSO_MAGIC);
        match saved {
            Some(v) => std::env::set_var(PSO_MAGIC_PREFIX_ENV, v),
            None => std::env::remove_var(PSO_MAGIC_PREFIX_ENV),
        }
    }
}
