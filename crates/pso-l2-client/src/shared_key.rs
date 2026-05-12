//! App. A shared-key derivation.
//!
//! Per the privacy-preserving L2 architecture spec, every SU has its
//! own per-SU keypair derived from the user's `consent_sk`, the SRA's
//! ephemeral public key `pk_cu`, and a 32-byte `su_nonce`:
//!
//! ```text
//! S          = ECDH(consent_sk, pk_cu)        // shared point
//! k_shared   = HKDF-SHA256(S.x, salt=su_nonce, info="")
//! shared_sk  = k_shared mod q                  // secp256k1 scalar
//! shared_pk  = shared_sk · G                   // secp256k1 point
//! ```
//!
//! The SRA derives the same `shared_sk` from its side using
//! `ECDH(sk_cu, consent_pk)` and then destroys `sk_cu`. Because ECDH
//! is symmetric (`sk · pk = sk · sk_other · G = sk_other · sk · G`),
//! both sides agree on `S`, and therefore on `shared_sk` after HKDF.
//!
//! The user-side function is what the wallet calls; the SRA-side
//! function is here for symmetry tests and for any future SRA Rust
//! integration that wants to reuse the same primitive.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{ProjectivePoint, PublicKey, SecretKey};
use sha2::Sha256;

use crate::error::L2ClientError;

/// Output of [`derive_shared_key`]. Both fields are derived from the
/// same scalar; callers usually want one or the other (the wallet
/// needs `secret` for signing, the chain side only ever sees the
/// `public` form materialised in the SU's `derivedOwner` field).
#[derive(Debug, Clone)]
pub struct SharedKey {
    /// Secret scalar — keep in memory only as long as the proving
    /// session, zeroize after use. We do not derive a `Drop` impl
    /// here because k256 internals don't expose zeroization on the
    /// scalar type; callers can wrap in `zeroize::Zeroizing` if
    /// stricter handling is needed.
    pub secret: SecretKey,
    /// Public point matching `secret`.
    pub public: PublicKey,
}

/// Wallet-side derivation: reconstruct the per-SU `shared_sk` from
/// the wallet's `consent_sk`, the SRA-supplied ephemeral `pk_cu`, and
/// the `su_nonce` decrypted from the SU receipt.
///
/// Mirrors the user-side branch of App. A.
pub fn derive_shared_key(
    consent_sk: &SecretKey,
    pk_cu: &PublicKey,
    su_nonce: &[u8; 32],
) -> Result<SharedKey, L2ClientError> {
    let shared_point = ecdh_x(consent_sk, pk_cu);
    let okm = hkdf_sha256(&shared_point, su_nonce)?;
    scalar_from_okm(&okm)
}

/// SRA-side derivation (mirrors the SRA branch of App. A). Same
/// output as [`derive_shared_key`] when called with the matching
/// counterparts (`sk_cu`, `consent_pk`, same `su_nonce`).
///
/// Currently only used by tests in this crate that exercise the
/// symmetry property; SRA production code lives in a separate
/// service. Kept here so the symmetry property is self-evident from
/// reading the public surface.
pub fn derive_shared_key_sra_side(
    sk_cu: &SecretKey,
    consent_pk: &PublicKey,
    su_nonce: &[u8; 32],
) -> Result<SharedKey, L2ClientError> {
    let shared_point = ecdh_x(sk_cu, consent_pk);
    let okm = hkdf_sha256(&shared_point, su_nonce)?;
    scalar_from_okm(&okm)
}

/// ECDH: returns the x-coordinate of `sk · pk` as 32 big-endian bytes,
/// the canonical input to HKDF per App. A.
///
/// Same access path `pso-integrations-shared::ecdh_multiply` uses,
/// stopping at the x-coordinate rather than serialising the full
/// SEC1 point.
fn ecdh_x(sk: &SecretKey, pk: &PublicKey) -> [u8; 32] {
    let shared = ProjectivePoint::from(*pk.as_affine()) * *sk.to_nonzero_scalar();
    let sec1 = shared.to_affine().to_sec1_point(false);
    let bytes = sec1.as_bytes();
    // SEC1 uncompressed = 0x04 || x (32) || y (32). x lives at [1..33].
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[1..33]);
    out
}

/// HKDF-SHA256 with `salt = nonce`, `ikm = ecdh_x`, empty info,
/// output 32 bytes. The spec's `encode(S.x)` is "32-byte big-endian"
/// — we feed that as IKM.
fn hkdf_sha256(ikm: &[u8; 32], salt: &[u8; 32]) -> Result<[u8; 32], L2ClientError> {
    // HKDF = Extract + Expand. For 32-byte output the Expand pass is
    // a single HMAC-SHA256 application; we inline both steps here
    // rather than pulling in a separate `hkdf` crate.
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(salt)
        .map_err(|e| L2ClientError::InvalidInput(format!("hkdf extract: {e}")))?;
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut expand = <Hmac<Sha256> as Mac>::new_from_slice(&prk)
        .map_err(|e| L2ClientError::InvalidInput(format!("hkdf expand: {e}")))?;
    expand.update(&[0x01]);
    let okm = expand.finalize().into_bytes();

    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    Ok(out)
}

/// Wrap the OKM as a secp256k1 secret key. `SecretKey::from_slice`
/// performs the canonical scalar reduction internally and rejects
/// zero — the failure mode the spec's `mod q` step worries about.
///
/// Note: HKDF output is uniform over 256 bits; secp256k1's order
/// `q` is very close to `2^256` (the bias is ~2^-128), so the
/// reduction is statistically indistinguishable from a uniformly
/// random scalar mod q. Acceptable per App. A.
fn scalar_from_okm(okm: &[u8; 32]) -> Result<SharedKey, L2ClientError> {
    let secret = SecretKey::from_slice(okm).map_err(|e| {
        L2ClientError::Witness(format!("shared scalar invalid: {e} — re-roll su_nonce"))
    })?;
    let public = secret.public_key();
    Ok(SharedKey { secret, public })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn random_secret_key() -> SecretKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SecretKey::from_slice(&bytes).expect("random 32 bytes form a valid scalar")
    }

    #[test]
    fn ecdh_is_symmetric() {
        let consent = random_secret_key();
        let sra_ephemeral = random_secret_key();
        let su_nonce: [u8; 32] = [0xab; 32];

        let user = derive_shared_key(&consent, &sra_ephemeral.public_key(), &su_nonce).unwrap();
        let sra =
            derive_shared_key_sra_side(&sra_ephemeral, &consent.public_key(), &su_nonce).unwrap();

        assert_eq!(
            user.secret.to_bytes(),
            sra.secret.to_bytes(),
            "App. A symmetry: user and SRA derivations must agree on shared_sk"
        );
        assert_eq!(
            user.public.to_sec1_bytes(),
            sra.public.to_sec1_bytes(),
            "shared_pk must match"
        );
    }

    #[test]
    fn different_nonces_yield_different_keys() {
        let consent = random_secret_key();
        let sra_eph = random_secret_key();
        let n1 = [0x01u8; 32];
        let n2 = [0x02u8; 32];

        let a = derive_shared_key(&consent, &sra_eph.public_key(), &n1).unwrap();
        let b = derive_shared_key(&consent, &sra_eph.public_key(), &n2).unwrap();
        assert_ne!(a.secret.to_bytes(), b.secret.to_bytes());
    }

    #[test]
    fn different_ephemerals_yield_different_keys() {
        let consent = random_secret_key();
        let sra_a = random_secret_key();
        let sra_b = random_secret_key();
        let nonce = [0xccu8; 32];

        let a = derive_shared_key(&consent, &sra_a.public_key(), &nonce).unwrap();
        let b = derive_shared_key(&consent, &sra_b.public_key(), &nonce).unwrap();
        assert_ne!(a.secret.to_bytes(), b.secret.to_bytes());
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let consent = random_secret_key();
        let sra_eph = random_secret_key();
        let nonce = [0xdeu8; 32];

        let a = derive_shared_key(&consent, &sra_eph.public_key(), &nonce).unwrap();
        let b = derive_shared_key(&consent, &sra_eph.public_key(), &nonce).unwrap();
        assert_eq!(a.secret.to_bytes(), b.secret.to_bytes());
    }
}
