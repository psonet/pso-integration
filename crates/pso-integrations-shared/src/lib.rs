#![forbid(unsafe_code)]

//! Shared cryptographic operations for PSO integration crates.
//!
//! Provides secp256k1 key parsing, ECDH key agreement, HMAC-SHA256 key
//! derivation, and a high-level [`derive_nft_keypair`] function used by
//! both `pso-mobile-integration` and `pso-sra-integration`.
//!
//! See [`witness`] for the ZK witness builders used by every prover in
//! the wallet stack -- assemble the byte-oriented `OwnershipWitness`
//! / `FullProofWitness` types defined in `pso-protocol` from a
//! Grumpkin keypair + Schnorr signature, plus the helper for flat
//! multi-SU aggregation. Off-chain Schnorr signing comes from
//! `pso-zk-circuit-noir::schnorr_grumpkin` (barretenberg-rs FFI).

pub mod witness;

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{ProjectivePoint, PublicKey, SecretKey};
use sha2::Sha256;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from shared cryptographic operations.
///
/// Consumer crates convert this to their own FFI-specific error types
/// via `From` impls.
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoOperation(String),
}

// ---------------------------------------------------------------------------
// Key parsing
// ---------------------------------------------------------------------------

/// Parse a secp256k1 secret key from either raw bytes or SEC1 DER.
///
/// - 32 bytes → interpreted as a raw scalar
/// - >32 bytes → interpreted as SEC1 DER (RFC 5915)
pub fn parse_secret_key_auto(bytes: &[u8]) -> Result<SecretKey, CryptoError> {
    if bytes.len() == 32 {
        parse_secret_key(bytes)
    } else {
        SecretKey::from_sec1_der(bytes)
            .map_err(|e| CryptoError::InvalidSecretKey(format!("not a valid SEC1 DER key: {}", e)))
    }
}

/// Parse a SEC1-encoded secp256k1 public key.
///
/// Accepts compressed (33 bytes) or uncompressed (65 bytes) form.
pub fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    PublicKey::from_sec1_bytes(bytes)
        .map_err(|e| CryptoError::InvalidPublicKey(format!("not a valid SEC1 public key: {}", e)))
}

/// Parse a secp256k1 secret key from a raw 32-byte scalar.
pub fn parse_secret_key(scalar: &[u8]) -> Result<SecretKey, CryptoError> {
    SecretKey::from_slice(scalar)
        .map_err(|e| CryptoError::InvalidSecretKey(format!("not a valid curve scalar: {}", e)))
}

// ---------------------------------------------------------------------------
// ECDH + KDF (App. A: ECDH-x → HKDF-SHA256 → reduce mod q_secp256k1)
// ---------------------------------------------------------------------------
//
// Spec ref. (privacy-preserving L2 architecture, App. A):
//
//     S         = ECDH(local_sk, remote_pk)        // shared point
//     k_shared  = HKDF-SHA256(salt=nonce, ikm=S.x, info="")
//     nft_sk    = k_shared mod q                    // secp256k1 scalar
//
// The previous implementation here used raw HMAC-SHA256 over the full
// 65-byte SEC1 point and emitted a different `nft_sk` than the bridge
// + wallet path in `pso-l2-client::shared_key`. The two surfaces are
// now unified on this spec-correct derivation; `pso-l2-client` is a
// thin wrapper around the helpers below.

/// ECDH x-coordinate: `(sk · pk).x` as 32 big-endian bytes.
///
/// The canonical App. A input to HKDF — stops at the x-coordinate
/// rather than serialising the full SEC1 point, which would change
/// the IKM and break interop with every spec-correct consumer.
pub fn ecdh_x(secret_key: &SecretKey, public_key: &PublicKey) -> [u8; 32] {
    let shared = ProjectivePoint::from(*public_key.as_affine()) * *secret_key.to_nonzero_scalar();
    let sec1 = shared.to_affine().to_sec1_point(false);
    let bytes = sec1.as_bytes();
    // SEC1 uncompressed = 0x04 || x (32) || y (32). x lives at [1..33].
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[1..33]);
    out
}

/// HKDF-SHA256 Extract+Expand for 32-byte output, empty `info`.
///
/// `salt` is App. A's per-SU `nonce`; `ikm` is the ECDH x-coordinate.
/// Inlined rather than pulling in the `hkdf` crate because for L=32
/// (single output block) Expand is a single HMAC application.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8]) -> Result<[u8; 32], CryptoError> {
    // Extract: prk = HMAC(key=salt, data=ikm)
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(salt)
        .map_err(|e| CryptoError::CryptoOperation(format!("HKDF extract init: {}", e)))?;
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    // Expand for L=32: okm = HMAC(key=prk, data="" || info || 0x01)
    // with info="" this is HMAC(prk, [0x01]).
    let mut expand = <Hmac<Sha256> as Mac>::new_from_slice(&prk)
        .map_err(|e| CryptoError::CryptoOperation(format!("HKDF expand init: {}", e)))?;
    expand.update(&[0x01]);
    let okm = expand.finalize().into_bytes();

    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    Ok(out)
}

// ---------------------------------------------------------------------------
// High-level: derive NFT keypair
// ---------------------------------------------------------------------------

/// Derive an NFT secret key from ECDH shared secret + nonce per App. A.
///
/// Performs: ECDH(local_sk, remote_pk) → HKDF-SHA256(salt=nonce,
/// ikm=S.x) → reduce mod q_secp256k1.
///
/// * `local_sk` — secp256k1 secret key: raw 32 bytes or SEC1 DER
/// * `remote_pk` — secp256k1 public key: compressed (33) or uncompressed (65)
/// * `nonce` — App. A salt; the spec mandates exactly 32 bytes
pub fn derive_nft_keypair(
    local_sk: &[u8],
    remote_pk: &[u8],
    nonce: &[u8],
) -> Result<SecretKey, CryptoError> {
    let secret_key = parse_secret_key_auto(local_sk)?;
    let public_key = parse_public_key(remote_pk)?;
    let x = ecdh_x(&secret_key, &public_key);
    let okm = hkdf_sha256(nonce, &x)?;
    parse_secret_key(&okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_secret_key() -> SecretKey {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SecretKey::from_slice(&b).expect("random bytes should form a valid key")
    }

    #[test]
    fn test_parse_secret_key_auto_from_der() {
        let der = SecretKey::from_slice(&[1u8; 32])
            .unwrap()
            .to_sec1_der()
            .unwrap();
        assert!(parse_secret_key_auto(der.as_ref()).is_ok());
    }

    #[test]
    fn test_parse_secret_key_auto_from_raw() {
        assert!(parse_secret_key_auto(&[1u8; 32]).is_ok());
    }

    #[test]
    fn test_parse_secret_key_auto_rejects_empty() {
        assert!(matches!(
            parse_secret_key_auto(&[]),
            Err(CryptoError::InvalidSecretKey(_))
        ));
    }

    #[test]
    fn test_parse_secret_key_auto_rejects_invalid_der() {
        assert!(matches!(
            parse_secret_key_auto(&[0xFFu8; 48]),
            Err(CryptoError::InvalidSecretKey(_))
        ));
    }

    #[test]
    fn test_parse_public_key_invalid() {
        assert!(matches!(
            parse_public_key(&[0x04u8; 64]),
            Err(CryptoError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn test_parse_public_key_compressed() {
        let sk = random_secret_key();
        assert!(parse_public_key(&sk.public_key().to_sec1_bytes()).is_ok());
    }

    #[test]
    fn test_ecdh_x_length_and_symmetry() {
        let sk_a = random_secret_key();
        let sk_b = random_secret_key();
        let x_ab = ecdh_x(&sk_a, &sk_b.public_key());
        let x_ba = ecdh_x(&sk_b, &sk_a.public_key());
        assert_eq!(x_ab.len(), 32);
        assert_eq!(x_ab, x_ba, "ECDH-x must be symmetric");
    }

    #[test]
    fn test_hkdf_determinism_and_length() {
        let okm1 = hkdf_sha256(&[2u8; 32], &[1u8; 32]).unwrap();
        let okm2 = hkdf_sha256(&[2u8; 32], &[1u8; 32]).unwrap();
        assert_eq!(okm1, okm2);
        assert_eq!(okm1.len(), 32);
        // Different salt → different output (well-known HKDF property,
        // pinned here so a regression in the salt argument-order is caught).
        let okm3 = hkdf_sha256(&[3u8; 32], &[1u8; 32]).unwrap();
        assert_ne!(okm1, okm3);
    }

    #[test]
    fn test_derive_nft_keypair_roundtrip() {
        let sk = random_secret_key();
        let pk_bytes = sk.public_key().to_sec1_bytes().to_vec();
        let sk_bytes = sk.to_bytes().to_vec();

        let nft_sk = derive_nft_keypair(&sk_bytes, &pk_bytes, &[42u8; 32]).unwrap();
        // Should produce the same result with the same inputs
        let nft_sk2 = derive_nft_keypair(&sk_bytes, &pk_bytes, &[42u8; 32]).unwrap();
        assert_eq!(nft_sk.to_bytes(), nft_sk2.to_bytes());
    }

    #[test]
    fn test_derive_nft_keypair_different_nonces() {
        let sk = random_secret_key();
        let pk_bytes = sk.public_key().to_sec1_bytes().to_vec();
        let sk_bytes = sk.to_bytes().to_vec();

        let nft_sk1 = derive_nft_keypair(&sk_bytes, &pk_bytes, &[1u8; 32]).unwrap();
        let nft_sk2 = derive_nft_keypair(&sk_bytes, &pk_bytes, &[2u8; 32]).unwrap();
        assert_ne!(nft_sk1.to_bytes(), nft_sk2.to_bytes());
    }

    /// Client and SRA independently derive the same NFT keypair via ECDH.
    ///
    /// ECDH guarantees: client_sk * sra_pk == sra_sk * client_pk.
    /// Both sides feed the same shared point + nonce into KDF, so the
    /// derived NFT secret key (and therefore public key) must match.
    #[test]
    fn test_client_sra_derive_same_keypair() {
        let client_sk = random_secret_key();
        let sra_sk = random_secret_key();
        let nonce = [7u8; 32];

        let client_pk_bytes = client_sk.public_key().to_sec1_bytes().to_vec();
        let sra_pk_bytes = sra_sk.public_key().to_sec1_bytes().to_vec();

        // Client: derive_nft_keypair(client_sk, sra_pk, nonce)
        let client_nft_sk =
            derive_nft_keypair(&client_sk.to_bytes(), &sra_pk_bytes, &nonce).unwrap();

        // SRA: derive_nft_keypair(sra_sk, client_pk, nonce)
        let sra_nft_sk = derive_nft_keypair(&sra_sk.to_bytes(), &client_pk_bytes, &nonce).unwrap();

        assert_eq!(client_nft_sk.to_bytes(), sra_nft_sk.to_bytes());
        assert_eq!(
            client_nft_sk.public_key().to_sec1_bytes(),
            sra_nft_sk.public_key().to_sec1_bytes(),
        );
    }

    /// Same ECDH symmetry test with compressed and uncompressed public keys.
    #[test]
    fn test_client_sra_derive_same_keypair_uncompressed_pk() {
        use k256::elliptic_curve::sec1::ToSec1Point;

        let client_sk = random_secret_key();
        let sra_sk = random_secret_key();
        let nonce = [99u8; 32];

        // Client sends compressed (33 bytes), SRA sends uncompressed (65 bytes)
        let client_pk_compressed = client_sk.public_key().to_sec1_bytes().to_vec();
        let sra_pk_uncompressed = sra_sk
            .public_key()
            .as_affine()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();

        let client_nft_sk =
            derive_nft_keypair(&client_sk.to_bytes(), &sra_pk_uncompressed, &nonce).unwrap();

        let sra_nft_sk =
            derive_nft_keypair(&sra_sk.to_bytes(), &client_pk_compressed, &nonce).unwrap();

        assert_eq!(client_nft_sk.to_bytes(), sra_nft_sk.to_bytes());
    }

    /// Different nonces produce different shared keys even with the same keypairs.
    #[test]
    fn test_client_sra_different_nonces_differ() {
        let client_sk = random_secret_key();
        let sra_sk = random_secret_key();

        let sra_pk_bytes = sra_sk.public_key().to_sec1_bytes().to_vec();
        let client_sk_bytes = client_sk.to_bytes().to_vec();

        let nft_sk1 = derive_nft_keypair(&client_sk_bytes, &sra_pk_bytes, &[1u8; 32]).unwrap();
        let nft_sk2 = derive_nft_keypair(&client_sk_bytes, &sra_pk_bytes, &[2u8; 32]).unwrap();

        assert_ne!(nft_sk1.to_bytes(), nft_sk2.to_bytes());
    }
}
