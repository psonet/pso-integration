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
    let nonce = ark_bn254::Fr::rand(&mut rand::rngs::OsRng);
    generate_ownership_inner(sra_sk, consent_pk, nonce)
}

/// Deterministic variant that accepts a fixed nonce for integration testing.
#[uniffi::export]
pub fn generate_nft_ownership_with_nonce(
    sra_sk: Vec<u8>,
    consent_pk: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<GeneratedOwnership, OwnershipError> {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    let nonce_bytes: [u8; 32] = nonce
        .try_into()
        .map_err(|_| OwnershipError::CryptoError("nonce must be exactly 32 bytes".to_string()))?;
    let nonce_fr: Fr = Fr::from_le_bytes_mod_order(&nonce_bytes);
    generate_ownership_inner(sra_sk, consent_pk, nonce_fr)
}

fn generate_ownership_inner(
    sra_sk: Vec<u8>,
    consent_pk: Vec<u8>,
    nonce_fr: ark_bn254::Fr,
) -> Result<GeneratedOwnership, OwnershipError> {
    use pso_integrations_shared::witness::{
        derive_grumpkin_public_key, fr_to_le32, reduce_to_grumpkin_sk,
    };

    let nonce_bytes = fr_to_le32(&nonce_fr);

    // App. A: secp256k1 ECDH + HKDF lands a 32-byte secret. Off-chain
    // ECDH stays on secp256k1 for wallet interop, but the resulting
    // 32-byte scalar is then reinterpreted as a Grumpkin scalar for
    // the in-circuit signing path. Reduce mod `q_Grumpkin` before
    // handing to barretenberg — bb 5.x's `schnorr_compute_public_key`
    // aborts the process on inputs >= q. Most valid secp256k1 keys
    // (the input distribution here) are above q_Grumpkin, so without
    // this reduction every call has ~80% probability of aborting.
    let nft_sk = pso_integrations_shared::derive_nft_keypair(&sra_sk, &consent_pk, &nonce_bytes)?;
    let nft_sk_raw: [u8; 32] = nft_sk.to_bytes().into();
    let nft_sk_bytes = reduce_to_grumpkin_sk(&nft_sk_raw);
    let grumpkin_key = derive_grumpkin_public_key(&nft_sk_bytes)
        .map_err(|e| OwnershipError::CryptoError(format!("derive grumpkin pk: {e}")))?;

    let ownership_fr = pso_protocol::ownership::compute_ownership_grumpkin(
        grumpkin_key.pk_x,
        grumpkin_key.pk_y,
        nonce_fr,
    )
    .map_err(|_| OwnershipError::CryptoError("ownership hash computation failed".to_string()))?;

    Ok(GeneratedOwnership {
        nonce: bs58::encode(fr_to_le32(&nonce_fr)).into_string(),
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

        // Expected outputs were regenerated after `generate_ownership_inner`
        // started reducing the HKDF/secp256k1 key mod `q_Grumpkin` before
        // the barretenberg call (bb 5.x aborts on out-of-range inputs;
        // most valid secp256k1 keys are above q_Grumpkin). Any downstream
        // cross-language consumer (the Kotlin integration test referenced
        // by the prior fixture string) needs to apply the same reduction
        // to match these values.
        assert_eq!(result.nonce, "3qbR1eZRqXUWroWKKYhbDmR3FfqTHfqSU8zZSxtANzYh");
        assert_eq!(
            result.ownership,
            "4JHqQcrjkRMy6pBNFKHBVoVCMEquq3rbXVBo3eX7h68d"
        );
    }

    #[test]
    fn test_deterministic_ownership_with_raw_key() {
        let result =
            generate_nft_ownership_with_nonce(vec![1u8; 32], test_consent_pk(), vec![42u8; 32])
                .unwrap();

        // Same inputs produce the same result regardless of key format.
        // See `test_deterministic_ownership_with_der_key` for why these
        // fixtures changed (mod-reduction added before bb FFI).
        assert_eq!(result.nonce, "3qbR1eZRqXUWroWKKYhbDmR3FfqTHfqSU8zZSxtANzYh");
        assert_eq!(
            result.ownership,
            "4JHqQcrjkRMy6pBNFKHBVoVCMEquq3rbXVBo3eX7h68d"
        );
    }
}
