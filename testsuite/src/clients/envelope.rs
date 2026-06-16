//! PSO anonymous-lane (users) `0x76` VdfProtectedTransaction envelope encoder.
//!
//! Mirrors the node's wire layout in
//! `pso-chain-research/crates/bft-node/src/pso/envelope.rs`:
//!
//! ```text
//! [1B  0x76 type byte]
//! [32B nullifier]
//! [32B vdf_input]
//! [4B  vdf_output length, big-endian][vdf_output bytes]
//! [4B  vdf_proof  length, big-endian][vdf_proof  bytes]
//! [8B  submitted_block, big-endian]
//! [..  inner standard tx, EIP-2718 encoded]
//! ```
//!
//! Unlike pso-chain's `0xCAFED00D` calldata-prefix scheme, the research node
//! carries the VDF fields on the transaction's own EIP-2718 wire envelope under
//! type byte `0x76`, wrapping the inner standard tx's 2718 bytes — the inner
//! calldata is left clean and the `0x76` envelope is metadata stripped by the
//! node, so the pooled identity equals the inner tx's hash.
//!
//! The chain re-derives `vdf_input` as
//! `SHA-256(signer || tx_nonce_le || submitted_block_le || chain_id_le)` and
//! validates the MinRoot proof against the current (or previous) epoch's `T`.
//! Wallets MUST use the exact same byte order or the validator rejects with
//! `BadVdfInputBinding` before even running the VDF verify.

use std::ops::Range;

use alloy::primitives::Address;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use pso_vdf::minroot::MinRootVdf;
use pso_vdf::types::VdfInput;
use pso_vdf::Vdf;

/// EIP-2718 type byte identifying a VDF-protected anonymous-lane envelope.
/// Mirrors `VDF_ENVELOPE_TYPE` on the node (replaces pso-chain's `0xCAFED00D`
/// calldata magic as the lane discriminator).
pub const VDF_ENVELOPE_TYPE: u8 = 0x76;

// Byte ranges into the full `0x76` wire envelope (type byte at index 0). The
// VDF output/proof are fixed 48-byte MinRoot/BLS12-381 values, so every field
// has a constant offset; the scenarios' tampering closures index via these.
/// 32-byte nullifier.
pub const NULLIFIER_RANGE: Range<usize> = 1..33;
/// 32-byte VDF input seed.
pub const VDF_INPUT_RANGE: Range<usize> = 33..65;
/// 48-byte VDF output (after its 4-byte length prefix at `65..69`).
pub const VDF_OUTPUT_RANGE: Range<usize> = 69..117;
/// 48-byte VDF proof (after its 4-byte length prefix at `117..121`).
pub const VDF_PROOF_RANGE: Range<usize> = 121..169;
/// 8-byte big-endian `submitted_block`.
pub const SUBMITTED_BLOCK_RANGE: Range<usize> = 169..177;
/// `vdf_input` through the end of the proof (including the constant length
/// prefixes) — the per-nonce VDF binding section S044 replays at a stale nonce.
pub const VDF_BINDING_RANGE: Range<usize> = 33..169;
/// Length of the wire up to (not including) the inner tx: type byte + header.
pub const ENVELOPE_PREFIX_LEN: usize = 177;

/// Canonical VDF input construction.
///
/// `vdf_input = SHA-256(signer_be_20 || tx_nonce_le_8 || submitted_block_le_8 || chain_id_le_8)`.
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

/// Build the full `0x76` VdfProtectedTransaction wire envelope wrapping
/// `inner_tx_2718` (the signed inner standard tx's EIP-2718 bytes).
///
/// Rolls a fresh 32-byte nullifier, derives `vdf_input` per the canonical
/// binding, runs MinRoot at `difficulty` iterations, and assembles
/// `0x76 || header || inner`. The returned bytes are ready to hex-encode into
/// `eth_sendRawTransaction`.
pub fn build_vdf_envelope(
    signer: Address,
    tx_nonce: u64,
    submitted_block: u64,
    chain_id: u64,
    difficulty: u64,
    inner_tx_2718: &[u8],
) -> eyre::Result<Vec<u8>> {
    if difficulty == 0 {
        return Err(eyre::eyre!("VDF difficulty must be > 0"));
    }

    let mut nullifier = [0u8; 32];
    OsRng.fill_bytes(&mut nullifier);

    let vdf_input_bytes = derive_vdf_input(signer, tx_nonce, submitted_block, chain_id);
    let vdf_input = VdfInput::from_bytes(vdf_input_bytes);
    let (vdf_output, vdf_proof) = MinRootVdf::eval(&vdf_input, difficulty);
    debug_assert_eq!(vdf_output.0.len(), 48, "VdfOutput is 48 bytes");
    debug_assert_eq!(vdf_proof.inner.len(), 48, "VdfProof is 48 bytes");

    let mut out = Vec::with_capacity(ENVELOPE_PREFIX_LEN + inner_tx_2718.len());
    out.push(VDF_ENVELOPE_TYPE);
    out.extend_from_slice(&nullifier);
    out.extend_from_slice(&vdf_input_bytes);
    out.extend_from_slice(&(vdf_output.0.len() as u32).to_be_bytes());
    out.extend_from_slice(&vdf_output.0);
    out.extend_from_slice(&(vdf_proof.inner.len() as u32).to_be_bytes());
    out.extend_from_slice(&vdf_proof.inner);
    out.extend_from_slice(&submitted_block.to_be_bytes());
    out.extend_from_slice(inner_tx_2718);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_has_correct_layout() {
        let signer = Address::from([0xab; 20]);
        let inner = vec![0x02u8, 0xde, 0xad, 0xbe, 0xef]; // stand-in inner 2718
        let env = build_vdf_envelope(signer, 0, 1, 1, 16, &inner).unwrap();
        assert_eq!(env[0], VDF_ENVELOPE_TYPE);
        assert_eq!(env.len(), ENVELOPE_PREFIX_LEN + inner.len());
        // output/proof length prefixes are the constant 48.
        assert_eq!(u32::from_be_bytes(env[65..69].try_into().unwrap()), 48);
        assert_eq!(u32::from_be_bytes(env[117..121].try_into().unwrap()), 48);
        assert_eq!(&env[ENVELOPE_PREFIX_LEN..], &inner[..]);
    }

    #[test]
    fn vdf_input_matches_canonical_binding() {
        let signer = Address::from([0xcd; 20]);
        let a = derive_vdf_input(signer, 7, 100, 9_900_501);
        let b = derive_vdf_input(signer, 7, 100, 9_900_501);
        assert_eq!(a, b);
        let c = derive_vdf_input(signer, 8, 100, 9_900_501);
        assert_ne!(a, c);
    }
}
