#![forbid(unsafe_code)]

//! FFI bindings for computing NFT ownership using Secp256K1 ECDH + Poseidon5.

mod error;

pub use error::OwnershipError;

use ark_ff::UniformRand;

uniffi::setup_scaffolding!();

/// Generated ownership values (nonce + ownership hash), both base58-encoded.
#[derive(uniffi::Record, Clone, Debug)]
pub struct GeneratedOwnership {
    pub nonce: String,
    pub ownership: String,
}

/// NFT keypair derived from ECDH shared secret + nonce.
#[derive(uniffi::Record, Clone, Debug)]
pub struct NftKeypair {
    /// Raw 32-byte secret key scalar.
    pub sk: Vec<u8>,
    /// SEC1-encoded public key (compressed, 33 bytes).
    pub pk: Vec<u8>,
}

/// Derive an NFT keypair from a local secret key, remote public key, and nonce.
///
/// * `local_sk` - Secp256K1 secret key: raw 32 bytes or SEC1 DER encoded
/// * `remote_pk` - Secp256K1 public key, compressed (33 bytes) or uncompressed (65 bytes)
/// * `nonce` - 32-byte nonce
#[uniffi::export]
pub fn derive_nft_keypair(
    local_sk: Vec<u8>,
    remote_pk: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<NftKeypair, OwnershipError> {
    let nft_sk = pso_integrations_shared::derive_nft_keypair(&local_sk, &remote_pk, &nonce)?;
    let nft_pk = nft_sk.public_key();

    Ok(NftKeypair {
        sk: nft_sk.to_bytes().to_vec(),
        pk: nft_pk.to_sec1_bytes().to_vec(),
    })
}

/// Generate NFT ownership value.
///
/// * `sra_sk` - Secp256K1 secret key: raw 32 bytes or SEC1 DER encoded
/// * `consent_pk` - Secp256K1 public key, compressed (33 bytes) or uncompressed (65 bytes)
#[uniffi::export]
pub fn generate_nft_ownership(
    sra_sk: Vec<u8>,
    consent_pk: Vec<u8>,
) -> Result<GeneratedOwnership, OwnershipError> {
    // Random Fr → 32 LE bytes. The Fr is by construction < q_BN254, so
    // these bytes round-trip back to the same Fr (no salt-vs-Poseidon
    // divergence below).
    let nonce_fr = ark_bn254::Fr::rand(&mut rand::rngs::OsRng);
    let nonce_bytes = pso_integrations_shared::witness::fr_to_le32(&nonce_fr);
    generate_ownership_inner(sra_sk, consent_pk, nonce_bytes)
}

/// Deterministic variant that accepts a fixed nonce for integration testing.
#[uniffi::export]
pub fn generate_nft_ownership_with_nonce(
    sra_sk: Vec<u8>,
    consent_pk: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<GeneratedOwnership, OwnershipError> {
    let nonce_bytes: [u8; 32] = nonce
        .try_into()
        .map_err(|_| OwnershipError::CryptoError("nonce must be exactly 32 bytes".to_string()))?;
    generate_ownership_inner(sra_sk, consent_pk, nonce_bytes)
}

fn generate_ownership_inner(
    sra_sk: Vec<u8>,
    consent_pk: Vec<u8>,
    nonce_bytes: [u8; 32],
) -> Result<GeneratedOwnership, OwnershipError> {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use pso_integrations_shared::witness::{
        derive_grumpkin_public_key, fr_to_le32, reduce_to_grumpkin_sk,
    };

    // Two distinct uses of the nonce:
    //
    // 1. As the **raw 32-byte** HKDF salt fed into App. A's KDF. This
    //    MUST match what the wallet uses verbatim; round-tripping
    //    through Fr first would reduce mod q_BN254 (lossy when the
    //    input >= q_BN254 — ~63% of uniform 32-byte values) and
    //    silently split the SRA-side and wallet-side derivations.
    // 2. As a **Fr field element** in the Poseidon ownership commit
    //    `Poseidon(pk_x, pk_y, nonce_fr)`. The on-chain consumer
    //    interprets the same bytes via `Fr::from_le_bytes_mod_order`.
    //
    // The earlier implementation fed the Fr-reduced bytes into HKDF,
    // which broke the symmetry property the App. A spec relies on.
    let nft_sk = pso_integrations_shared::derive_nft_keypair(&sra_sk, &consent_pk, &nonce_bytes)?;
    let nft_sk_raw: [u8; 32] = nft_sk.to_bytes().into();

    // bb 5.x's `schnorr_compute_public_key` aborts on inputs >= q_Grumpkin
    // (most valid secp256k1 keys land in that range), so reduce here.
    let nft_sk_bytes = reduce_to_grumpkin_sk(&nft_sk_raw);
    let grumpkin_key = derive_grumpkin_public_key(&nft_sk_bytes)
        .map_err(|e| OwnershipError::CryptoError(format!("derive grumpkin pk: {e}")))?;

    let nonce_fr = Fr::from_le_bytes_mod_order(&nonce_bytes);
    let ownership_fr = pso_protocol::ownership::compute_ownership_grumpkin(
        grumpkin_key.pk_x,
        grumpkin_key.pk_y,
        nonce_fr,
    )
    .map_err(|_| OwnershipError::CryptoError("ownership hash computation failed".to_string()))?;

    Ok(GeneratedOwnership {
        // Echo the input bytes verbatim — not the Fr round-trip — so
        // the caller's `nonce` field matches what they (and the
        // wallet) use as the HKDF salt.
        nonce: bs58::encode(nonce_bytes).into_string(),
        ownership: bs58::encode(fr_to_le32(&ownership_fr)).into_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_consent_pk() -> Vec<u8> {
        let sk = k256::SecretKey::from_slice(&[1u8; 32]).unwrap();
        sk.public_key().to_sec1_bytes().to_vec()
    }

    #[test]
    fn test_deterministic_ownership_with_der_key() {
        let sra_sk = pso_integrations_shared::parse_secret_key(&[1u8; 32])
            .unwrap()
            .to_sec1_der()
            .unwrap()
            .to_vec();

        let result =
            generate_nft_ownership_with_nonce(sra_sk, test_consent_pk(), vec![42u8; 32]).unwrap();

        // Fixtures regenerated after the App. A KDF was unified on the
        // spec-correct HKDF-SHA256(salt=nonce, ikm=ECDH-x) path. The
        // prior raw-HMAC-over-full-SEC1-point implementation in
        // `pso-integrations-shared` produced a different `nft_sk` than
        // the wallet/bridge derivation in `pso-l2-client::shared_key`,
        // silently splitting on-chain commitments across two
        // surfaces. Cross-language consumers MUST regenerate their
        // own fixtures and republish — the prior value
        // (`4JHqQcrjkRMy6pBNFKHBVoVCMEquq3rbXVBo3eX7h68d`) was the
        // diverged variant and never matched anything minted by the
        // bridge.
        assert_eq!(result.nonce, "3qbR1eZRqXUWroWKKYhbDmR3FfqTHfqSU8zZSxtANzYh");
        assert_eq!(
            result.ownership,
            "6Joic5TBR6H9uDoc2BsGZbu4cBNucXHeDQ7BnV8thTh1"
        );
    }

    #[test]
    fn test_deterministic_ownership_with_raw_key() {
        let result =
            generate_nft_ownership_with_nonce(vec![1u8; 32], test_consent_pk(), vec![42u8; 32])
                .unwrap();

        // Same inputs produce the same result regardless of key format.
        // See `test_deterministic_ownership_with_der_key` for the
        // context behind this fixture value.
        assert_eq!(result.nonce, "3qbR1eZRqXUWroWKKYhbDmR3FfqTHfqSU8zZSxtANzYh");
        assert_eq!(
            result.ownership,
            "6Joic5TBR6H9uDoc2BsGZbu4cBNucXHeDQ7BnV8thTh1"
        );
    }
}
