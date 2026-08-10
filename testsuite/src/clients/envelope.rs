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

use alloy_primitives::Address;
use rand::rngs::OsRng;
use rand::RngCore;

use pso_antispam::PowScheme;
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

/// Canonical input construction, delegated to the shared admission contract.
///
/// `input = SHA-256(signer_20 || tx_nonce_le_8 || submitted_block_le_8 || chain_id_le_8)`.
///
/// This used to be re-implemented here, byte for byte, alongside the node's
/// copy and `pso-vdf`'s. Three hand-written copies of the one rule a client and
/// a node MUST agree on — and a divergence between them is invisible: the
/// transaction is simply never admitted, and nothing on either side says why.
/// The suite now derives it the same way the node does, from the same crate,
/// so a test passing here means the node would agree.
pub fn derive_vdf_input(
    signer: Address,
    tx_nonce: u64,
    submitted_block: u64,
    chain_id: u64,
) -> [u8; 32] {
    pso_antispam::derive_input_from(signer.0 .0, tx_nonce, submitted_block, chain_id).0
}

/// EIP-2718 type byte for the SR-43 scheme-tagged anonymous-lane envelope.
///
/// Mirrors `POW_ENVELOPE_TYPE` on the node. It exists ALONGSIDE `0x76` rather
/// than replacing it: deployed clients already sign the legacy format, so the
/// old byte keeps parsing while they migrate.
pub const POW_ENVELOPE_TYPE: u8 = 0x77;

// Byte ranges into a `0x77` envelope carrying a HASHCASH solution. Unlike the
// `0x76` constants above these are scheme-dependent — hashcash's solution is 8
// bytes, and a future scheme's will not be — so anything generic must derive
// offsets from `PowScheme::solution_len()` rather than reuse these.
/// 32-byte nullifier.
pub const POW_NULLIFIER_RANGE: Range<usize> = 1..33;
/// 1-byte scheme tag.
pub const POW_SCHEME_INDEX: usize = 33;
/// 8-byte hashcash solution (after its 4-byte length prefix at `34..38`).
pub const POW_SOLUTION_RANGE: Range<usize> = 38..46;
/// 8-byte big-endian `submitted_block`.
pub const POW_SUBMITTED_BLOCK_RANGE: Range<usize> = 46..54;
/// Wire length up to (not including) the inner tx, for a hashcash solution.
pub const POW_ENVELOPE_PREFIX_LEN: usize = 54;

/// Build a `0x77` anti-spam envelope wrapping `inner_tx_2718`.
///
/// ```text
/// 0x77 ‖ nullifier(32) ‖ scheme(1) ‖ len(solution) u32-BE ‖ solution
///      ‖ submitted_block(8 BE) ‖ inner
/// ```
///
/// Note what is NOT on the wire: `vdf_input`. It is derived from
/// signer/nonce/block/chain on both sides, which is what binds the solution to
/// one submission — a field that is computed cannot be lied about, so the
/// legacy format's explicit copy and its separate binding check both disappear.
///
/// The solution is produced through [`PowScheme::solve_into`], not by calling
/// hashcash directly, so this suite exercises the same scheme-generic path a
/// real wallet uses.
pub fn build_pow_envelope(
    signer: Address,
    tx_nonce: u64,
    submitted_block: u64,
    chain_id: u64,
    difficulty: u64,
    inner_tx_2718: &[u8],
) -> eyre::Result<Vec<u8>> {
    build_pow_envelope_with(
        PowScheme::Hashcash,
        signer,
        tx_nonce,
        submitted_block,
        chain_id,
        difficulty,
        inner_tx_2718,
    )
}

/// [`build_pow_envelope`] with an explicit scheme — so a scenario can build an
/// envelope tagged with a scheme the node refuses (the retired MinRoot tag)
/// and assert the refusal, which is not reachable through the happy path.
pub fn build_pow_envelope_with(
    scheme: PowScheme,
    signer: Address,
    tx_nonce: u64,
    submitted_block: u64,
    chain_id: u64,
    difficulty: u64,
    inner_tx_2718: &[u8],
) -> eyre::Result<Vec<u8>> {
    if difficulty == 0 {
        return Err(eyre::eyre!("anti-spam difficulty must be > 0"));
    }

    let mut nullifier = [0u8; 32];
    OsRng.fill_bytes(&mut nullifier);

    let input = derive_vdf_input(signer, tx_nonce, submitted_block, chain_id);
    let mut solution = vec![0u8; scheme.solution_len()];
    if !scheme.solve_into(&input, difficulty, &mut solution) {
        // Only reachable for a retired scheme; the caller wants the bytes
        // anyway, to assert the node refuses them.
        solution.iter_mut().for_each(|b| *b = 0);
    }

    let mut out = Vec::with_capacity(POW_ENVELOPE_PREFIX_LEN + inner_tx_2718.len());
    out.push(POW_ENVELOPE_TYPE);
    out.extend_from_slice(&nullifier);
    out.push(scheme.tag());
    out.extend_from_slice(&(solution.len() as u32).to_be_bytes());
    out.extend_from_slice(&solution);
    out.extend_from_slice(&submitted_block.to_be_bytes());
    out.extend_from_slice(inner_tx_2718);
    Ok(out)
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

    /// The name of this test promises more than it used to check: determinism
    /// and "a different nonce gives a different answer" both hold for a binding
    /// that has silently diverged from the node's. Since a divergence is
    /// invisible at runtime — the transaction is simply never admitted, with no
    /// error on either side — the canonical bytes are pinned here.
    ///
    /// This vector predates the move to `pso-antispam` and is what `pso-vdf`
    /// produced. If it fails, the suite and the node no longer agree, and every
    /// scenario that submits a users-lane transaction is testing a fiction.
    /// Pins the `0x77` layout against a real built envelope. The tamper
    /// scenarios index by these constants, so a wrong offset would not fail
    /// loudly — it would quietly corrupt a different field and the test would
    /// still "pass" for the wrong reason.
    #[test]
    fn pow_envelope_has_correct_layout() {
        let signer = Address::from([0xab; 20]);
        let inner = vec![0x02u8, 0xde, 0xad, 0xbe, 0xef];
        let env = build_pow_envelope(signer, 0, 1, 1, 64, &inner).unwrap();

        assert_eq!(env[0], POW_ENVELOPE_TYPE);
        assert_eq!(env.len(), POW_ENVELOPE_PREFIX_LEN + inner.len());
        assert_eq!(env[POW_SCHEME_INDEX], PowScheme::Hashcash.tag());
        // The 4-byte length prefix sits between the tag and the solution.
        assert_eq!(
            u32::from_be_bytes(env[34..38].try_into().unwrap()) as usize,
            PowScheme::Hashcash.solution_len()
        );
        assert_eq!(
            POW_SOLUTION_RANGE.len(),
            PowScheme::Hashcash.solution_len(),
            "the solution range must match the scheme's pinned width"
        );
        assert_eq!(
            u64::from_be_bytes(env[POW_SUBMITTED_BLOCK_RANGE].try_into().unwrap()),
            1
        );
        assert_eq!(&env[POW_ENVELOPE_PREFIX_LEN..], &inner[..]);

        // The solution must actually solve the canonical binding — otherwise
        // the happy-path scenario would be asserting nothing.
        let input = derive_vdf_input(signer, 0, 1, 1);
        assert!(PowScheme::Hashcash.verify(&input, &env[POW_SOLUTION_RANGE], 64));
    }

    /// `vdf_input` is deliberately absent from the `0x77` wire: both sides
    /// derive it. If it ever reappeared, the field could disagree with the
    /// derivation and the binding check would be back to trusting a client.
    #[test]
    fn the_pow_envelope_does_not_carry_the_derived_input() {
        let signer = Address::from([0xab; 20]);
        let env = build_pow_envelope(signer, 0, 1, 1, 64, &[0x02]).unwrap();
        let input = derive_vdf_input(signer, 0, 1, 1);
        assert!(
            !env.windows(32).any(|w| w == input),
            "the derived input must not appear on the 0x77 wire"
        );
    }

    #[test]
    fn vdf_input_matches_canonical_binding() {
        let signer = Address::from([0xcd; 20]);
        let a = derive_vdf_input(signer, 7, 100, 9_900_501);
        assert_eq!(
            hex::encode(a),
            "bd99052f200b07d860273cb1ae689fb8b64eef287b89fa237d0ea938c1a872e4",
            "the canonical binding changed — the suite and the node now disagree"
        );

        assert_eq!(
            a,
            derive_vdf_input(signer, 7, 100, 9_900_501),
            "deterministic"
        );
        // Each bound field must move the result, or the replay it prevents is
        // possible.
        assert_ne!(a, derive_vdf_input(signer, 8, 100, 9_900_501), "nonce");
        assert_ne!(a, derive_vdf_input(signer, 7, 101, 9_900_501), "block");
        assert_ne!(a, derive_vdf_input(signer, 7, 100, 9_900_502), "chain");
        assert_ne!(
            a,
            derive_vdf_input(Address::from([0xce; 20]), 7, 100, 9_900_501),
            "signer"
        );
    }
}
