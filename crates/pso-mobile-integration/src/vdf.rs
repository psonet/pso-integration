//! MinRoot VDF FFI for mobile wallets.
//!
//! Wallets attach a VDF proof to every Users-pool transaction so the
//! sequencer can rate-limit submissions by sequential-compute cost
//! (REQ-VDF-01..05). This module exposes the slow `eval` and fast
//! `verify` operations from `pso-vdf` to React Native via UniFFI.
//!
//! ## Workflow
//!
//! 1. Pull a fresh L2 block height (`submitted_block`) from the node.
//! 2. Call [`derive_vdf_input`] to construct the canonical 32-byte
//!    seed — `SHA-256(signer || nonce_le || submitted_block_le || chain_id_le)`.
//! 3. Call [`compute_vdf`] on a background thread. This takes ~2 s on
//!    iPhone 13 hardware at `T_BASE`; never run it on the UI thread.
//! 4. Attach `VdfResult.output` and `VdfResult.proof` to the Users-pool
//!    transaction's `vdfOutput` / `vdfProof` fields. Also broadcast
//!    `submitted_block` so the validator can re-derive the same input.
//!
//! ## Sanity checks
//!
//! - [`verify_vdf`] is a fast (~ms) round-trip check the wallet runs
//!   before broadcasting, just in case `compute_vdf` was interrupted
//!   or the bytes got corrupted on the way out.
//! - [`is_vdf_block_valid`] mirrors the validator's backward-looking
//!   window — wallets can check whether a stale proof is still
//!   accepted before re-running the slow path.

use pso_vdf::minroot::MinRootVdf;
use pso_vdf::params::VdfParams;
use pso_vdf::types::{VdfInput, VdfOutput};
use pso_vdf::Vdf;

use crate::types::{MobileError, VdfConstants, VdfResult};

/// Construct the canonical 32-byte VDF input the validator expects.
///
/// `vdf_input = SHA-256(signer_be_20 || nonce_le_8 || submitted_block_le_8 || chain_id_le_8)`.
///
/// Wallets must use this exact construction — the validator rejects
/// any mismatch with `BadVdfInputBinding`. See
/// `pso_vdf::params::VdfParams::derive_input_from`.
///
/// # Inputs
///
/// - `signer`: 20-byte EVM address (big-endian).
/// - `tx_nonce`: EVM tx nonce of the transaction this proof binds to.
/// - `submitted_block`: L2 block height the wallet observed when
///   computing the proof.
/// - `chain_id`: PSO chain id (devnet `19_280_501`, etc.).
#[uniffi::export]
pub fn derive_vdf_input(
    signer: Vec<u8>,
    tx_nonce: u64,
    submitted_block: u64,
    chain_id: u64,
) -> Result<Vec<u8>, MobileError> {
    let signer: [u8; 20] =
        signer
            .as_slice()
            .try_into()
            .map_err(|_| MobileError::InvalidVdfInput {
                detail: format!("signer must be 20 bytes, got {}", signer.len()),
            })?;
    let input = VdfParams::derive_input_from(signer, tx_nonce, submitted_block, chain_id);
    Ok(input.as_bytes().to_vec())
}

/// Compute the MinRoot VDF over `input` with `difficulty` sequential
/// iterations. **Slow path** — ~2 seconds at `T_BASE` on iPhone 13.
/// Run on a background thread.
///
/// `input` must be exactly 32 bytes (typically the output of
/// [`derive_vdf_input`]). `difficulty` must be > 0; pass [`vdf_constants`]'s
/// `t_base` for the default, or whatever value the node reports for the
/// current epoch.
#[uniffi::export]
pub fn compute_vdf(input: Vec<u8>, difficulty: u64) -> Result<VdfResult, MobileError> {
    if difficulty == 0 {
        return Err(MobileError::InvalidVdfDifficulty {
            detail: "difficulty must be > 0".to_string(),
        });
    }
    let input_bytes: [u8; 32] =
        input
            .as_slice()
            .try_into()
            .map_err(|_| MobileError::InvalidVdfInput {
                detail: format!("input must be 32 bytes, got {}", input.len()),
            })?;
    let vdf_input = VdfInput::from_bytes(input_bytes);
    let (output, proof) = MinRootVdf::eval(&vdf_input, difficulty);
    Ok(VdfResult {
        output: output.0,
        proof: proof.inner,
    })
}

/// Verify a MinRoot VDF proof. **Fast path** — ~ms on any device.
///
/// Wallets run this as a sanity check on their own output before
/// broadcasting (cheap insurance against corruption between the
/// background thread and the network layer). The sequencer runs the
/// same call under REQ-VDF-02.
///
/// Returns `true` iff `(output, proof)` is a valid proof of
/// `output = MinRoot(input, difficulty)`.
#[uniffi::export]
pub fn verify_vdf(
    input: Vec<u8>,
    output: Vec<u8>,
    proof: Vec<u8>,
    difficulty: u64,
) -> Result<bool, MobileError> {
    if difficulty == 0 {
        return Err(MobileError::InvalidVdfDifficulty {
            detail: "difficulty must be > 0".to_string(),
        });
    }
    let input_bytes: [u8; 32] =
        input
            .as_slice()
            .try_into()
            .map_err(|_| MobileError::InvalidVdfInput {
                detail: format!("input must be 32 bytes, got {}", input.len()),
            })?;
    let vdf_input = VdfInput::from_bytes(input_bytes);
    let vdf_output = VdfOutput::from_bytes(output);
    let vdf_proof = pso_vdf::minroot::MinRootProof::from_bytes(proof).map_err(|e| {
        MobileError::InvalidVdfInput {
            detail: format!("malformed proof bytes: {e}"),
        }
    })?;
    Ok(MinRootVdf::verify(
        &vdf_input,
        &vdf_output,
        &vdf_proof,
        difficulty,
    ))
}

/// Check whether `submitted_block` is still within the validator's
/// backward-looking acceptance window relative to `current_block`.
///
/// `window` defaults to `PROOF_VALIDITY_WINDOW` (32 blocks ≈ 64s at
/// 2s block time) — see [`vdf_constants`]. Wallets call this to decide
/// whether a previously-computed proof is still fresh enough to
/// broadcast, or whether they need to re-run the slow path against a
/// newer `submitted_block`.
#[uniffi::export]
pub fn is_vdf_block_valid(submitted_block: u64, current_block: u64, window: u64) -> bool {
    VdfParams::is_block_valid(submitted_block, current_block, window)
}

/// Return the VDF parameters compiled into this client.
///
/// Wallets surface these to UI ("Proof difficulty: T = ...") and use
/// `t_base` as the default difficulty when the node hasn't reported a
/// dynamic value yet.
#[uniffi::export]
pub fn vdf_constants() -> VdfConstants {
    VdfConstants {
        t_base: pso_vdf::T_BASE,
        max_difficulty_adjustment_pct: pso_vdf::MAX_DIFFICULTY_ADJUSTMENT_PCT,
        epoch_length_blocks: pso_vdf::EPOCH_LENGTH_BLOCKS,
        proof_validity_window: pso_vdf::PROOF_VALIDITY_WINDOW,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_signer() -> Vec<u8> {
        vec![0xab; 20]
    }

    #[test]
    fn derive_input_is_deterministic() {
        let signer = sample_signer();
        let a = derive_vdf_input(signer.clone(), 7, 100, 19_280_501).unwrap();
        let b = derive_vdf_input(signer, 7, 100, 19_280_501).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn derive_input_rejects_wrong_signer_length() {
        let err = derive_vdf_input(vec![0u8; 19], 0, 0, 1).unwrap_err();
        assert!(matches!(err, MobileError::InvalidVdfInput { .. }));
    }

    #[test]
    fn derive_input_sensitive_to_fields() {
        let signer = sample_signer();
        let base = derive_vdf_input(signer.clone(), 7, 100, 19_280_501).unwrap();
        let alt_nonce = derive_vdf_input(signer.clone(), 8, 100, 19_280_501).unwrap();
        let alt_block = derive_vdf_input(signer.clone(), 7, 101, 19_280_501).unwrap();
        let alt_chain = derive_vdf_input(signer, 7, 100, 19_280_502).unwrap();
        assert_ne!(base, alt_nonce);
        assert_ne!(base, alt_block);
        assert_ne!(base, alt_chain);
    }

    /// Tiny-T round-trip — keeps the suite fast. Real callers use
    /// `T_BASE = 100_000`; this asserts the surface wires through to
    /// `pso-vdf` correctly, not the calibration.
    #[test]
    fn compute_then_verify_tiny_difficulty() {
        let input = derive_vdf_input(sample_signer(), 1, 1, 1).unwrap();
        let result = compute_vdf(input.clone(), 16).unwrap();

        assert_eq!(result.output.len(), VdfOutput::MINROOT_LEN);
        assert!(!result.proof.is_empty());

        let ok = verify_vdf(input, result.output.clone(), result.proof, 16).unwrap();
        assert!(ok, "self-produced VDF proof must verify");
    }

    #[test]
    fn verify_rejects_tampered_output() {
        let input = derive_vdf_input(sample_signer(), 1, 1, 1).unwrap();
        let mut result = compute_vdf(input.clone(), 8).unwrap();
        result.output[0] ^= 0xFF;
        let ok = verify_vdf(input, result.output, result.proof, 8).unwrap();
        assert!(!ok, "tampered output must fail verification");
    }

    #[test]
    fn compute_rejects_zero_difficulty() {
        let input = derive_vdf_input(sample_signer(), 0, 0, 1).unwrap();
        let err = compute_vdf(input, 0).unwrap_err();
        assert!(matches!(err, MobileError::InvalidVdfDifficulty { .. }));
    }

    #[test]
    fn block_validity_matches_pso_vdf() {
        // current=100, window=32 → accept [68, 100]
        assert!(is_vdf_block_valid(100, 100, 32));
        assert!(is_vdf_block_valid(68, 100, 32));
        assert!(!is_vdf_block_valid(67, 100, 32));
        assert!(!is_vdf_block_valid(101, 100, 32));
    }

    #[test]
    fn vdf_constants_match_upstream() {
        let c = vdf_constants();
        assert_eq!(c.t_base, pso_vdf::T_BASE);
        assert_eq!(
            c.max_difficulty_adjustment_pct,
            pso_vdf::MAX_DIFFICULTY_ADJUSTMENT_PCT,
        );
        assert_eq!(c.epoch_length_blocks, pso_vdf::EPOCH_LENGTH_BLOCKS);
        assert_eq!(c.proof_validity_window, pso_vdf::PROOF_VALIDITY_WINDOW);
    }
}
