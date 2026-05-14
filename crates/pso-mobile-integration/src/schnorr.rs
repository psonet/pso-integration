//! Schnorr-on-Grumpkin primitive FFI surface.
//!
//! Exposes the two raw operations a client needs to construct or
//! cross-check the Grumpkin Schnorr signature an in-circuit
//! `schnorr::verify_signature` constraint expects:
//!
//! - [`schnorr_sign_grumpkin`] — produce a 64-byte (s || e) signature
//!   over a 32-byte big-endian message digest.
//! - [`schnorr_verify_grumpkin`] — verify the same shape off-chain
//!   without going through a Noir proof.
//!
//! ## Wire formats
//!
//! All `Vec<u8>` parameters are positional, fixed-length:
//!
//! - `secret_key` (sign): 32 bytes, raw little-endian-ish — the exact
//!   bytes returned in [`NftKeypair::sk`] from [`crate::derive_nft_keypair`].
//!   Internally we hand them straight to barretenberg-rs's
//!   `schnorr_construct_signature`, which interprets them as a Grumpkin
//!   scalar reduced mod `q_Grumpkin`.
//! - `public_key` (verify): 64 bytes, layout `pk_x_le || pk_y_le` — the
//!   exact bytes returned in [`NftKeypair::pk`] from
//!   [`crate::derive_nft_keypair`]. Each coord is a 32-byte LE Fr
//!   encoding. We swap to barretenberg's BE wire format internally.
//! - `message`: exactly 32 bytes, big-endian. By convention this is
//!   `Poseidon2(nft_hash, nonce).to_be_bytes()` for ownership
//!   witnesses — the same byte string the in-circuit
//!   `schnorr::verify_signature` consumes as its `message: [u8; 32]`.
//!   The FFI surface stays generic: callers who want to sign anything
//!   else just pass any 32-byte digest.
//! - `signature` (verify) / return value (sign): 64 bytes, layout
//!   `s_be || e_be` — exactly the buffer
//!   [`pso_zk_circuit_noir::schnorr_grumpkin::schnorr_sign_be`]
//!   produces.
//!
//! ## Why this is useful from the FFI
//!
//! See `pso-integration/testsuite/src/scenarios/s001_happy_flow.rs`
//! plus `crates/pso-l2-client/src/wallet.rs::prepare_su_ownership_material`
//! — those wire the same primitives into a full witness construction
//! flow. With this module a non-Rust client can mirror that flow:
//! derive the keypair via [`crate::derive_nft_keypair`], compute its
//! own message digest (Poseidon2 of nft_hash + nonce, or whatever the
//! circuit expects), sign here, and feed the 64-byte signature into a
//! custom witness builder. Verify is exposed for symmetry — useful for
//! unit tests, debugging, and cross-checking a signature before
//! submission.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use barretenberg_rs::{
    backends::FfiBackend, generated_types::GrumpkinPoint, BarretenbergApi,
};

use pso_integrations_shared::witness::fr_to_be32;
use pso_zk_circuit_noir::schnorr_grumpkin::schnorr_sign_be;

use crate::types::MobileError;

/// Sign a 32-byte big-endian message digest with Grumpkin Schnorr.
///
/// Returns a 64-byte signature `s || e` matching the layout the Noir
/// `schnorr::verify_signature` constraint and on-chain
/// `TributeDraft.submit` aggregation witness consume.
#[uniffi::export]
pub fn schnorr_sign_grumpkin(
    secret_key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, MobileError> {
    let sk: [u8; 32] = secret_key
        .as_slice()
        .try_into()
        .map_err(|_| MobileError::InvalidSecretKey {
            detail: format!(
                "secret_key must be 32 bytes, got {}",
                secret_key.len()
            ),
        })?;
    let msg: [u8; 32] = message
        .as_slice()
        .try_into()
        .map_err(|_| MobileError::Internal {
            detail: format!("message must be 32 bytes, got {}", message.len()),
        })?;
    // `schnorr_sign_be` takes the digest as an `Fr` and BE-encodes it
    // internally before handing it to bb. We came in as raw BE bytes,
    // so decode-into-Fr is the inverse of fr_to_be32 — round-trips
    // exactly because the helper pads/truncates symmetrically.
    let digest_fr = Fr::from_be_bytes_mod_order(&msg);
    let sig = schnorr_sign_be(&sk, &digest_fr).map_err(|e| MobileError::Internal {
        detail: format!("schnorr_sign: {e}"),
    })?;
    Ok(sig.to_vec())
}

/// Verify a Grumpkin Schnorr signature against a 32-byte big-endian
/// digest. Returns `true` if the signature is valid.
///
/// `public_key` is 64 bytes in the same LE layout
/// [`crate::derive_nft_keypair`] returns: `pk_x_le || pk_y_le`.
#[uniffi::export]
pub fn schnorr_verify_grumpkin(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, MobileError> {
    if public_key.len() != 64 {
        return Err(MobileError::InvalidPublicKey {
            detail: format!(
                "public_key must be 64 bytes (pk_x_le||pk_y_le), got {}",
                public_key.len()
            ),
        });
    }
    if message.len() != 32 {
        return Err(MobileError::Internal {
            detail: format!("message must be 32 bytes, got {}", message.len()),
        });
    }
    if signature.len() != 64 {
        return Err(MobileError::Internal {
            detail: format!(
                "signature must be 64 bytes (s||e, each 32B BE), got {}",
                signature.len()
            ),
        });
    }

    // Convert the FFI-side LE Fr encodings into the BE wire format
    // barretenberg expects. Round-trip via Fr so we don't trust the
    // raw bytes are canonical (a malformed input would still be
    // safely rejected by bb, but reducing here gives a cleaner error
    // boundary).
    let pk_x_le: [u8; 32] = public_key[0..32].try_into().expect("len checked");
    let pk_y_le: [u8; 32] = public_key[32..64].try_into().expect("len checked");
    let pk_x_fr = Fr::from_le_bytes_mod_order(&pk_x_le);
    let pk_y_fr = Fr::from_le_bytes_mod_order(&pk_y_le);
    let pk = GrumpkinPoint {
        x: fr_to_be32(&pk_x_fr).to_vec(),
        y: fr_to_be32(&pk_y_fr).to_vec(),
    };

    let s_be: &[u8] = &signature[0..32];
    let e_be: &[u8] = &signature[32..64];

    let mut api = api_handle()?;
    let resp = api
        .schnorr_verify_signature(&message, pk, s_be, e_be)
        .map_err(|e| MobileError::Internal {
            detail: format!("schnorr_verify: {e}"),
        })?;
    Ok(resp.verified)
}

fn api_handle() -> Result<BarretenbergApi<FfiBackend>, MobileError> {
    let backend = FfiBackend::new().map_err(|e| MobileError::Internal {
        detail: format!("bb FfiBackend: {e}"),
    })?;
    Ok(BarretenbergApi::new(backend))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use pso_integrations_shared::witness::{fr_to_le32, random_grumpkin_key};
    use rand::rngs::OsRng;

    fn pk_le_bytes(
        key: &pso_integrations_shared::witness::GrumpkinKey,
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(&fr_to_le32(&key.pk_x));
        v.extend_from_slice(&fr_to_le32(&key.pk_y));
        v
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let key = random_grumpkin_key().expect("random key");
        let digest = Fr::rand(&mut OsRng);
        let msg = fr_to_be32(&digest).to_vec();

        let sig = schnorr_sign_grumpkin(key.sk_bytes.to_vec(), msg.clone())
            .expect("sign must succeed");
        assert_eq!(sig.len(), 64);

        let ok = schnorr_verify_grumpkin(pk_le_bytes(&key), msg, sig)
            .expect("verify call must succeed");
        assert!(ok, "valid signature must verify");
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let key = random_grumpkin_key().expect("random key");
        let digest = Fr::rand(&mut OsRng);
        let msg = fr_to_be32(&digest).to_vec();
        let sig = schnorr_sign_grumpkin(key.sk_bytes.to_vec(), msg)
            .expect("sign must succeed");

        // Tamper: sign over one digest, verify against a different one.
        let other_digest = Fr::rand(&mut OsRng);
        let other_msg = fr_to_be32(&other_digest).to_vec();
        let ok = schnorr_verify_grumpkin(pk_le_bytes(&key), other_msg, sig)
            .expect("verify call must succeed");
        assert!(!ok, "tampered message must not verify");
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let key = random_grumpkin_key().expect("random key");
        let digest = Fr::rand(&mut OsRng);
        let msg = fr_to_be32(&digest).to_vec();
        let mut sig = schnorr_sign_grumpkin(key.sk_bytes.to_vec(), msg.clone())
            .expect("sign must succeed");

        // Flip one bit in the signature's `s` portion.
        sig[0] ^= 0x01;
        let ok = schnorr_verify_grumpkin(pk_le_bytes(&key), msg, sig)
            .expect("verify call must succeed");
        assert!(!ok, "bit-flipped signature must not verify");
    }

    #[test]
    fn sign_rejects_short_secret_key() {
        let err = schnorr_sign_grumpkin(vec![0u8; 16], vec![0u8; 32])
            .expect_err("must reject short sk");
        assert!(matches!(err, MobileError::InvalidSecretKey { .. }));
    }

    #[test]
    fn verify_rejects_short_public_key() {
        let err = schnorr_verify_grumpkin(vec![0u8; 32], vec![0u8; 32], vec![0u8; 64])
            .expect_err("must reject short pk");
        assert!(matches!(err, MobileError::InvalidPublicKey { .. }));
    }
}
