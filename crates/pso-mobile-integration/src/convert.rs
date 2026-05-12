//! Conversion utilities between FFI boundary types and internal domain types.
//!
//! Each function translates one mobile-friendly type (`Vec<u8>`, `String`, `u16`)
//! to the corresponding internal representation (`Fr`, `NaiveDate`, `Currency`, etc.).

use ark_bn254::Fr;
use ark_ff::PrimeField;
use chrono::NaiveDate;
use iso_currency::Currency;
use k256::elliptic_curve::SecretKey;
use k256::Secp256k1;
use pso_integrations_shared::witness::fr_to_le32;
use pso_poseidon::PoseidonHasher;

use pso_protocol::merkle::{MerklePathElement, MerklePathElementIndex};

use crate::types::{MerklePathElementInput, MobileError, ProofResult};

// -- Secret key --

/// Parse a secp256k1 secret key from raw 32-byte representation.
pub fn parse_secret_key(bytes: &[u8]) -> Result<SecretKey<Secp256k1>, MobileError> {
    SecretKey::from_slice(bytes).map_err(|e| MobileError::InvalidSecretKey {
        detail: e.to_string(),
    })
}

// -- Field element (Fr) --

/// Parse a BN254 Fr from 32 little-endian bytes.
pub fn bytes_to_fr(bytes: &[u8]) -> Result<Fr, MobileError> {
    let arr: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| MobileError::InvalidFieldElement {
            detail: format!("expected 32 bytes, got {}", bytes.len()),
        })?;
    Ok(Fr::from_le_bytes_mod_order(arr))
}

/// Convert an Fr to 32 little-endian bytes.
pub fn fr_to_bytes(fr: &Fr) -> Vec<u8> {
    fr_to_le32(fr).to_vec()
}

/// Parse a `Vec<Vec<u8>>` into `Vec<Fr>`.
pub fn bytes_vec_to_fr_vec(vecs: &[Vec<u8>]) -> Result<Vec<Fr>, MobileError> {
    vecs.iter().map(|v| bytes_to_fr(v)).collect()
}

// -- Date --

/// Parse a `u32` in YYYYMMDD format to `NaiveDate`.
pub fn parse_worldwide_day(value: u32) -> Result<NaiveDate, MobileError> {
    let day = value % 100;
    let month = (value / 100) % 100;
    let year = value / 10000;
    NaiveDate::from_ymd_opt(year as i32, month, day).ok_or_else(|| MobileError::InvalidDate {
        detail: format!("invalid YYYYMMDD date: {}", value),
    })
}

// -- Worldwide day --

/// Epoch for worldwide day count (2021-01-01).
///
/// Mirrors `pso_nft`'s private `wwd_epoch()`.
fn wwd_epoch() -> NaiveDate {
    NaiveDate::from_ymd_opt(2021, 1, 1).expect("2021-01-01 is a valid date")
}

/// Convert a `NaiveDate` to worldwide day count (days since 2021-01-01).
///
/// Mirrors `pso_nft`'s private `worldwide_day_count()`.
pub fn worldwide_day_count(date: &NaiveDate) -> u64 {
    (*date - wwd_epoch()).num_days() as u64
}

// -- Currency --

/// Parse a u16 ISO 4217 numeric code to `Currency`.
pub fn parse_currency(code: u16) -> Result<Currency, MobileError> {
    Currency::from_numeric(code).ok_or_else(|| MobileError::InvalidCurrency {
        detail: format!("unknown ISO 4217 numeric code: {}", code),
    })
}

// -- Merkle path --

/// Convert `MerklePathElementInput` slice to `Vec<MerklePathElement>`.
pub fn parse_merkle_path(
    elements: &[MerklePathElementInput],
) -> Result<Vec<MerklePathElement>, MobileError> {
    elements
        .iter()
        .map(|e| {
            let node_hash: [u8; 32] = e.node_hash.as_slice().try_into().map_err(|_| {
                MobileError::InvalidFieldElement {
                    detail: format!(
                        "merkle node hash must be 32 bytes, got {}",
                        e.node_hash.len()
                    ),
                }
            })?;
            let index = match e.index {
                0 => MerklePathElementIndex::Skip,
                1 => MerklePathElementIndex::Left,
                2 => MerklePathElementIndex::Right,
                other => {
                    return Err(MobileError::InvalidMerkleIndex {
                        detail: format!("expected 0, 1, or 2, got {}", other),
                    })
                }
            };
            Ok(MerklePathElement { node_hash, index })
        })
        .collect()
}

// -- Tribute Draft ID --

/// Compute TributeDraft ID: `Poseidon2(owner, wwd_fr)`.
///
/// Mirrors `pso_nft::compute_inputs::compute_tribute_draft_id` (private module).
pub fn compute_tribute_draft_id(owner: &Fr, wwd: &Fr) -> Result<Fr, MobileError> {
    let mut poseidon =
        pso_poseidon::Poseidon::<Fr>::new_circom(2).map_err(|e| MobileError::Internal {
            detail: e.to_string(),
        })?;
    poseidon
        .hash(&[*owner, *wwd])
        .map_err(|e| MobileError::Internal {
            detail: e.to_string(),
        })
}

// -- Proof result --

/// Convert a `NoirProof` into the FFI-safe `ProofResult`.
pub fn noir_proof_to_result(proof: &pso_zk_circuit_noir::NoirProof) -> ProofResult {
    ProofResult {
        proof: proof.proof.clone(),
        public_inputs: proof.public_inputs.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::rngs::OsRng;

    #[test]
    fn test_parse_worldwide_day_valid() {
        let date = parse_worldwide_day(20260305).unwrap();
        assert_eq!(date, NaiveDate::from_ymd_opt(2026, 3, 5).unwrap());
    }

    #[test]
    fn test_parse_worldwide_day_invalid_values() {
        assert!(parse_worldwide_day(20261301).is_err()); // month 13
        assert!(parse_worldwide_day(20260230).is_err()); // Feb 30
        assert!(parse_worldwide_day(0).is_err());
    }

    #[test]
    fn test_worldwide_day_count_epoch() {
        let epoch = NaiveDate::from_ymd_opt(2021, 1, 1).unwrap();
        assert_eq!(worldwide_day_count(&epoch), 0);
    }

    #[test]
    fn test_worldwide_day_count_known_date() {
        let date = NaiveDate::from_ymd_opt(2021, 1, 2).unwrap();
        assert_eq!(worldwide_day_count(&date), 1);

        let date = NaiveDate::from_ymd_opt(2022, 1, 1).unwrap();
        assert_eq!(worldwide_day_count(&date), 365);
    }

    #[test]
    fn test_bytes_to_fr_roundtrip() {
        let original = Fr::rand(&mut OsRng);
        let bytes = fr_to_bytes(&original);
        let recovered = bytes_to_fr(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bytes_to_fr_invalid_length() {
        assert!(bytes_to_fr(&[0u8; 31]).is_err());
        assert!(bytes_to_fr(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_bytes_to_fr_zero() {
        let zero_bytes = fr_to_bytes(&Fr::from(0u64));
        let recovered = bytes_to_fr(&zero_bytes).unwrap();
        assert_eq!(recovered, Fr::from(0u64));
    }

    #[test]
    fn test_parse_currency_eur() {
        let currency = parse_currency(978).unwrap();
        assert_eq!(currency, Currency::EUR);
    }

    #[test]
    fn test_parse_currency_invalid() {
        assert!(parse_currency(9999).is_err());
    }

    #[test]
    fn test_parse_merkle_path_valid() {
        let fr = Fr::rand(&mut OsRng);
        let elements = vec![
            MerklePathElementInput {
                node_hash: fr_to_le32(&fr).to_vec(),
                index: 1,
            },
            MerklePathElementInput {
                node_hash: fr_to_le32(&fr).to_vec(),
                index: 2,
            },
        ];
        let path = parse_merkle_path(&elements).unwrap();
        assert_eq!(path.len(), 2);
        assert_eq!(path[0].index, MerklePathElementIndex::Left);
        assert_eq!(path[1].index, MerklePathElementIndex::Right);
    }

    #[test]
    fn test_parse_merkle_path_invalid_index() {
        let fr = Fr::rand(&mut OsRng);
        let elements = vec![MerklePathElementInput {
            node_hash: fr_to_le32(&fr).to_vec(),
            index: 3,
        }];
        assert!(parse_merkle_path(&elements).is_err());
    }

    #[test]
    fn test_parse_merkle_path_invalid_hash_length() {
        let elements = vec![MerklePathElementInput {
            node_hash: vec![0u8; 16],
            index: 1,
        }];
        assert!(parse_merkle_path(&elements).is_err());
    }

    #[test]
    fn test_compute_tribute_draft_id_deterministic() {
        let owner = Fr::rand(&mut OsRng);
        let wwd = Fr::from(1889u64);
        let id1 = compute_tribute_draft_id(&owner, &wwd).unwrap();
        let id2 = compute_tribute_draft_id(&owner, &wwd).unwrap();
        assert_eq!(id1, id2);
    }
}
