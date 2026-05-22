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

use k256::{PublicKey, SecretKey};

use pso_integrations_shared::{ecdh_x, hkdf_sha256, parse_secret_key, CryptoError};

use crate::error::L2ClientError;

impl From<CryptoError> for L2ClientError {
    fn from(err: CryptoError) -> Self {
        L2ClientError::Witness(format!("shared-key derive: {err}"))
    }
}

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
    derive_shared_key_inner(consent_sk, pk_cu, su_nonce)
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
    derive_shared_key_inner(sk_cu, consent_pk, su_nonce)
}

/// Shared inner. The two public entry points exist purely for
/// readability at call sites — the math is symmetric so the
/// implementation is identical.
fn derive_shared_key_inner(
    local_sk: &SecretKey,
    remote_pk: &PublicKey,
    su_nonce: &[u8; 32],
) -> Result<SharedKey, L2ClientError> {
    // App. A primitives live in `pso-integrations-shared` so the
    // bridge / wallet / UniFFI surfaces all derive the same value.
    // See the module doc above for the spec recipe.
    let x = ecdh_x(local_sk, remote_pk);
    let okm = hkdf_sha256(su_nonce, &x)?;
    let secret = parse_secret_key(&okm)
        .map_err(|e| L2ClientError::Witness(format!("shared scalar invalid: {e}")))?;
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
