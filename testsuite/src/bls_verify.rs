//! Off-chain verification that an IMT root is signed by the chain's BFT
//! committee — the cryptographic core of the S046 cert-inclusion scenario.
//!
//! The chain finalizes each block with a BLS12-381 **MinSig** threshold
//! signature (signature ∈ G1, group public key ∈ G2) over
//! `union_unique(finalize_namespace, proposal_bytes)`, where the proposal's
//! digest is the block digest that folds `r` (the IMT root). We verify that
//! recovered certificate against the group public key the L1 `DaInbox` holds.
//!
//! We deliberately use the SAME crate the chain signs with
//! (`commonware-cryptography`, MinSig, RFC-9380 hash-to-curve, identical DST),
//! so the check is byte-compatible by construction rather than a re-derivation.
//! The only glue is decompressing the DaInbox's EIP-2537 G2 layout (256 bytes)
//! into commonware's 96-byte compressed point — the reverse of the chain's
//! `pso_l1_deployer::bls::g2_compressed_to_eip2537`.

use blst::{blst_fp, blst_fp2, blst_fp_from_bendian, blst_p2_affine, blst_p2_affine_compress};
use commonware_codec::extensions::DecodeExt;
use commonware_cryptography::bls12381::primitives::{
    ops::verify_message,
    variant::{MinSig, Variant},
};

/// The chain's finalize namespace: `NAMESPACE ‖ "_FINALIZE"` =
/// `b"_PSO_CHAIN" ‖ b"_FINALIZE"`. Mirrors commonware's `finalize_namespace`
/// and `pso_l1_deployer::cert::finalize_namespace`.
pub const FINALIZE_NAMESPACE: &[u8] = b"_PSO_CHAIN_FINALIZE";

/// Encode a `u64` as commonware-codec LEB128 varint (7 data bits per byte,
/// high bit = continuation). Mirrors `commonware_codec::varint::UInt` /
/// `pso_l1_deployer::cert::uint_varint`.
fn uint_varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out
}

/// `proposal_bytes = uint(epoch) ‖ uint(view) ‖ uint(parent) ‖ digest[32]`
/// (commonware `Proposal::write`: round epoch, view, parent view, then the
/// 32-byte payload digest). The message half of the finalize signature.
pub fn proposal_bytes(epoch: u64, view: u64, parent: u64, digest: &[u8; 32]) -> Vec<u8> {
    let mut out = uint_varint(epoch);
    out.extend_from_slice(&uint_varint(view));
    out.extend_from_slice(&uint_varint(parent));
    out.extend_from_slice(digest);
    out
}

/// Read one 48-byte big-endian coordinate from a 64-byte EIP-2537 field slot
/// (16 zero pad ‖ 48-byte coordinate) into a `blst_fp`.
fn fp_from_eip2537_slot(slot: &[u8]) -> blst_fp {
    let mut fp = blst_fp::default();
    // SAFETY: `slot` is 64 bytes, so `slot[16..64]` is exactly the 48 bytes
    // blst_fp_from_bendian reads.
    unsafe { blst_fp_from_bendian(&mut fp, slot[16..64].as_ptr()) };
    fp
}

/// Convert a DaInbox EIP-2537 G2 group key (256 bytes, layout
/// `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`, each 64 B = 16 zero bytes ‖ 48-byte BE
/// coordinate) into the 96-byte compressed encoding commonware decodes. The
/// reverse of the chain's `g2_compressed_to_eip2537`.
pub fn g2_eip2537_to_compressed(eip: &[u8]) -> eyre::Result<[u8; 96]> {
    if eip.len() != 256 {
        return Err(eyre::eyre!(
            "EIP-2537 G2 group key must be 256 bytes, got {}",
            eip.len()
        ));
    }
    let affine = blst_p2_affine {
        x: blst_fp2 {
            fp: [
                fp_from_eip2537_slot(&eip[0..64]),
                fp_from_eip2537_slot(&eip[64..128]),
            ],
        },
        y: blst_fp2 {
            fp: [
                fp_from_eip2537_slot(&eip[128..192]),
                fp_from_eip2537_slot(&eip[192..256]),
            ],
        },
    };
    let mut out = [0u8; 96];
    // SAFETY: `out` is 96 bytes (compressed G2 length); `affine` is fully
    // initialized above.
    unsafe { blst_p2_affine_compress(out.as_mut_ptr(), &affine) };
    Ok(out)
}

/// Verify the committee finalize signature `cert_sig_compressed` (compressed
/// G1, 48 B) over the finalize message for `(round_epoch, round_view,
/// parent_view, tip_digest)`, against the DaInbox group public key
/// `group_pubkey_eip2537` (EIP-2537 G2, 256 B). `Ok(())` iff the threshold
/// signature verifies — i.e. ≥2f+1 of the committee finalized that digest.
pub fn verify_finalize_cert(
    group_pubkey_eip2537: &[u8],
    round_epoch: u64,
    round_view: u64,
    parent_view: u64,
    tip_digest: &[u8; 32],
    cert_sig_compressed: &[u8],
) -> eyre::Result<()> {
    let pk_compressed = g2_eip2537_to_compressed(group_pubkey_eip2537)?;
    let public = <MinSig as Variant>::Public::decode(pk_compressed.as_ref())
        .map_err(|e| eyre::eyre!("decode group public key (G2): {e}"))?;
    let sig = <MinSig as Variant>::Signature::decode(cert_sig_compressed)
        .map_err(|e| eyre::eyre!("decode cert signature (G1, expect 48B compressed): {e}"))?;
    let msg = proposal_bytes(round_epoch, round_view, parent_view, tip_digest);
    verify_message::<MinSig>(&public, FINALIZE_NAMESPACE, &msg, &sig)
        .map_err(|e| eyre::eyre!("committee finalize signature failed to verify: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_cryptography::bls12381::primitives::ops::{keypair, sign_message};

    /// Mirror of the chain's `g2_compressed_to_eip2537` (test-only) so we can
    /// build a 256-byte EIP-2537 input from a real compressed G2, then check
    /// our reverse conversion reproduces the exact compressed bytes.
    fn g2_compressed_to_eip2537(compressed: &[u8]) -> [u8; 256] {
        use blst::{blst_bendian_from_fp, blst_p2_affine, blst_p2_uncompress, BLST_ERROR};
        let mut affine = blst_p2_affine::default();
        // SAFETY: `compressed` is 96 bytes; blst validates the encoding.
        let err = unsafe { blst_p2_uncompress(&mut affine, compressed.as_ptr()) };
        assert_eq!(err, BLST_ERROR::BLST_SUCCESS, "uncompress G2");
        let fp_to = |fp: &blst_fp| -> [u8; 64] {
            let mut be = [0u8; 48];
            // SAFETY: `be` is exactly 48 bytes.
            unsafe { blst_bendian_from_fp(be.as_mut_ptr(), fp) };
            let mut out = [0u8; 64];
            out[16..].copy_from_slice(&be);
            out
        };
        let mut out = [0u8; 256];
        out[0..64].copy_from_slice(&fp_to(&affine.x.fp[0]));
        out[64..128].copy_from_slice(&fp_to(&affine.x.fp[1]));
        out[128..192].copy_from_slice(&fp_to(&affine.y.fp[0]));
        out[192..256].copy_from_slice(&fp_to(&affine.y.fp[1]));
        out
    }

    #[test]
    fn finalize_cert_verifies_via_eip2537_group_key() {
        // Sign a finalize message with a real MinSig keypair, then verify it
        // the way S046 will: through the EIP-2537 -> compressed -> commonware
        // group-key path. Validates the proposal/LEB128 encoding, the G2
        // conversion, and the commonware decode + verify wiring — no devnet.
        let (private, public) = keypair::<_, MinSig>(&mut rand::thread_rng());

        let (epoch, view, parent) = (7u64, 9u64, 3u64);
        let digest = [0x5au8; 32];
        let msg = proposal_bytes(epoch, view, parent, &digest);
        let sig = sign_message::<MinSig>(&private, FINALIZE_NAMESPACE, &msg);

        // Direct commonware verify (sanity).
        verify_message::<MinSig>(&public, FINALIZE_NAMESPACE, &msg, &sig)
            .expect("direct commonware verify must pass");

        // Round-trip the public key compressed -> EIP-2537 -> compressed and
        // assert byte-exact, then that it still decodes to the same point.
        let compressed = public.encode();
        let eip = g2_compressed_to_eip2537(compressed.as_ref());
        let compressed2 = g2_eip2537_to_compressed(&eip).expect("eip2537 -> compressed");
        assert_eq!(
            compressed.as_ref(),
            &compressed2[..],
            "EIP-2537 round-trip must reproduce the compressed G2"
        );

        // Full S046 path: verify through the EIP-2537 group key + compressed sig.
        let sig_compressed = sig.encode();
        verify_finalize_cert(&eip, epoch, view, parent, &digest, sig_compressed.as_ref())
            .expect("verify_finalize_cert via EIP-2537 group key must pass");

        // Negative: a tampered digest must fail.
        let mut bad = digest;
        bad[0] ^= 0x01;
        assert!(
            verify_finalize_cert(&eip, epoch, view, parent, &bad, sig_compressed.as_ref()).is_err(),
            "verify must reject a tampered digest"
        );
    }
}
