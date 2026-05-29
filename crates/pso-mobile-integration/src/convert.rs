//! Conversion utilities between FFI boundary types and internal domain types.
//!
//! Each function translates one mobile-friendly type (`Vec<u8>`, `String`, `u16`)
//! to the corresponding internal representation (`Fr`, `NaiveDate`, `Currency`, etc.).

use ark_bn254::{Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use chrono::NaiveDate;
use iso_currency::Currency;
use pso_integrations_shared::witness::{derive_grumpkin_public_key, fr_to_be32, GrumpkinKey};
use pso_poseidon::PoseidonHasher;

use pso_protocol::merkle::{MerklePathElement, MerklePathElementIndex};

use crate::types::{MerklePathElementInput, MobileError, ProofResult};

// -- Grumpkin secret key --

/// Gate: is `sk_bytes` (big-endian) a usable Grumpkin secret key?
///
/// A valid key is a non-zero scalar strictly less than the Grumpkin
/// scalar field order `q_Grumpkin` (which equals BN254's base field
/// `Fq` modulus — Grumpkin's scalar field is BN254's base field by
/// construction).
///
/// This MUST be checked before any 32-byte secret key reaches
/// barretenberg-rs (`schnorr_compute_public_key` /
/// `schnorr_construct_signature`): bb 5.x aborts the entire process
/// with an uncatchable C++ exception on any input `>= q_Grumpkin`, so
/// an unchecked out-of-range key from a client crashes the app instead
/// of surfacing a recoverable error. Roughly 63% of uniformly random
/// 32-byte values land `>= q_Grumpkin`, so this is a live hazard, not a
/// theoretical one. Clients that want a guaranteed-valid key should use
/// [`generate_tribute_key`](crate::api::generate_tribute_key) rather
/// than rolling their own 32 random bytes.
pub fn grumpkin_sk_in_range(sk_bytes: &[u8; 32]) -> bool {
    // The zero scalar has no valid public key; reject it explicitly.
    if sk_bytes.iter().all(|&b| b == 0) {
        return false;
    }
    // `from_be_bytes_mod_order` reduces mod `q_Grumpkin`. If the input
    // was already `< q`, re-encoding the reduced value to 32 big-endian
    // bytes reproduces the input exactly; if it was `>= q`, the
    // reduction changed it and the canonical form differs. So an
    // unchanged round-trip is precisely "the input was in range".
    let reduced = Fq::from_be_bytes_mod_order(sk_bytes);
    let be = reduced.into_bigint().to_bytes_be();
    let mut canonical = [0u8; 32];
    let off = 32 - be.len().min(32);
    canonical[off..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
    &canonical == sk_bytes
}

/// Validate a 32-byte Grumpkin secret key, erroring (instead of letting
/// barretenberg abort the process) when it is out of range. Returns the
/// fixed-size array on success so callers can hand it straight to the
/// FFI.
pub fn check_grumpkin_sk(bytes: &[u8]) -> Result<[u8; 32], MobileError> {
    let sk_arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| MobileError::InvalidSecretKey {
            detail: format!("expected 32-byte Grumpkin secret key, got {}", bytes.len()),
        })?;
    if !grumpkin_sk_in_range(&sk_arr) {
        return Err(MobileError::SecretKeyOutOfRange {
            detail: "secret key must be a non-zero scalar < q_Grumpkin (BN254 Fq modulus); \
                     reduce it or use generate_tribute_key"
                .to_string(),
        });
    }
    Ok(sk_arr)
}

/// Parse a Grumpkin secret key from raw 32-byte representation and
/// derive the matching public key via the barretenberg-rs FFI.
///
/// The bytes are gated through [`check_grumpkin_sk`] first, so an
/// out-of-range key yields a recoverable [`MobileError::SecretKeyOutOfRange`]
/// rather than aborting the process inside barretenberg.
pub fn parse_secret_key(bytes: &[u8]) -> Result<GrumpkinKey, MobileError> {
    let sk_arr = check_grumpkin_sk(bytes)?;
    derive_grumpkin_public_key(&sk_arr).map_err(|e| MobileError::InvalidSecretKey {
        detail: e.to_string(),
    })
}

// -- Field element (Fr) --

/// Parse a BN254 Fr from 32 big-endian bytes.
///
/// BE is the canonical wire format across every public PSO surface
/// (UniFFI inputs, on-chain calldata, aggregation-proof PI prefix,
/// barretenberg-rs Grumpkin signatures). The internal Noir witness
/// vector still uses LE — that's a circuit-contract detail walled
/// off by the `witness::*` helpers in `pso-integrations-shared`.
pub fn bytes_to_fr(bytes: &[u8]) -> Result<Fr, MobileError> {
    let arr: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| MobileError::InvalidFieldElement {
            detail: format!("expected 32 bytes, got {}", bytes.len()),
        })?;
    Ok(Fr::from_be_bytes_mod_order(arr))
}

/// Convert an Fr to 32 big-endian bytes.
pub fn fr_to_bytes(fr: &Fr) -> Vec<u8> {
    fr_to_be32(fr).to_vec()
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
/// `node_hash` bytes are BE-encoded Fr — same convention as the
/// rest of the PSO wire format (pso-protocol v0.3+ interprets them
/// via `Fr::from_be_bytes_mod_order` in `compute_merkle_root`).
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
                node_hash: fr_to_be32(&fr).to_vec(),
                index: 1,
            },
            MerklePathElementInput {
                node_hash: fr_to_be32(&fr).to_vec(),
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
            node_hash: fr_to_be32(&fr).to_vec(),
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

    /// 32-byte big-endian encoding of `q_Grumpkin` (= BN254 `Fq`
    /// modulus). Anything `>= this` is out of range.
    fn q_grumpkin_be() -> [u8; 32] {
        let be = Fq::MODULUS.to_bytes_be();
        let mut out = [0u8; 32];
        let off = 32 - be.len().min(32);
        out[off..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
        out
    }

    #[test]
    fn test_grumpkin_sk_in_range_rejects_zero() {
        assert!(!grumpkin_sk_in_range(&[0u8; 32]));
    }

    #[test]
    fn test_grumpkin_sk_in_range_accepts_one() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(grumpkin_sk_in_range(&one));
    }

    #[test]
    fn test_grumpkin_sk_in_range_rejects_all_ff() {
        // 2^256 - 1 is far above q_Grumpkin (~2^254).
        assert!(!grumpkin_sk_in_range(&[0xffu8; 32]));
    }

    #[test]
    fn test_grumpkin_sk_in_range_boundary() {
        // q itself is out of range; q - 1 is the largest valid key.
        let q = q_grumpkin_be();
        assert!(!grumpkin_sk_in_range(&q));

        let mut q_minus_one = q;
        // q is odd (prime), so the LSB is 1 and q - 1 just clears it.
        assert_eq!(q_minus_one[31] & 1, 1);
        q_minus_one[31] -= 1;
        assert!(grumpkin_sk_in_range(&q_minus_one));
    }

    #[test]
    fn test_check_grumpkin_sk_wrong_length() {
        let err = check_grumpkin_sk(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, MobileError::InvalidSecretKey { .. }));
    }

    #[test]
    fn test_check_grumpkin_sk_out_of_range() {
        let err = check_grumpkin_sk(&[0xffu8; 32]).unwrap_err();
        assert!(matches!(err, MobileError::SecretKeyOutOfRange { .. }));
    }

    #[test]
    fn test_check_grumpkin_sk_in_range_ok() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(check_grumpkin_sk(&one).unwrap(), one);
    }
}
