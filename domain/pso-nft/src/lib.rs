//! NFT domain types and test data generation for the PSO proof system.
//!
//! Defines `TributeDraft` and `SpendingUnit` NFT types with their
//! serialization, witness generation, and random test data generation
//! via the `Generated` and `OwnerGenerated` traits.

use anyhow::anyhow;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use chrono::{NaiveDate, TimeDelta, Utc};
use iso_currency::Currency;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};

use pso_integrations_shared::witness::GrumpkinKey;
use pso_protocol::merkle::{MerklePathElement, MerklePathElementIndex};
use pso_protocol::witness::{HashableNFT, OwnableNFT};

use crate::compute_inputs::{
    compute_spending_unit_hash, compute_tribute_draft_hash, compute_tribute_draft_id,
};

/// Encode an `Fr` as 32 little-endian bytes (right-padded with zeros).
fn fr_to_le32(value: &Fr) -> [u8; 32] {
    let le = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let n = le.len().min(32);
    out[..n].copy_from_slice(&le[..n]);
    out
}

/// Compute the Poseidon3 ownership commitment from a Grumpkin keypair
/// and a nonce. Thin wrapper around
/// `pso_protocol::ownership::compute_ownership_grumpkin`.
fn ownership_from_grumpkin_key(key: &GrumpkinKey, nonce: Fr) -> anyhow::Result<Fr> {
    pso_protocol::ownership::compute_ownership_grumpkin(key.pk_x, key.pk_y, nonce)
        .map_err(|e| anyhow!("compute_ownership_grumpkin: {e}"))
}

// -- Test data generation types --

/// Bundles an NFT with the auxiliary data needed for witness generation.
///
/// Nonce and owner keys are privacy-sensitive and are NOT part of the NFT
/// data model. They are only needed at witness generation time.
#[derive(Debug)]
pub struct GeneratedNFTData<T> {
    pub nft: T,
    pub owner_keys: Owner,
    pub nonce: Fr,
}

/// Generate a random NFT with associated keys and nonce.
pub trait Generated {
    fn generate(rng: &mut OsRng) -> anyhow::Result<GeneratedNFTData<Self>>
    where
        Self: Sized;
}

/// Generate an NFT with a specific owner key pair.
pub trait OwnerGenerated: Generated {
    fn generate_with_owner(owner: Owner, rng: &mut OsRng) -> anyhow::Result<GeneratedNFTData<Self>>
    where
        Self: Sized;
}

/// Generate a random Merkle path for testing (not part of any NFT).
pub fn generate_test_merkle_path(rng: &mut OsRng) -> Vec<MerklePathElement> {
    let merkle_depth: u64 = rng.gen_range(4..8);
    let mut merkle_path = Vec::with_capacity(merkle_depth as usize);
    for _ in 0..merkle_depth {
        let coin_flip = rng.gen_bool(0.5);
        let random_hash = Fr::rand(&mut *rng);

        merkle_path.push(MerklePathElement {
            node_hash: fr_to_le32(&random_hash),
            index: if coin_flip {
                MerklePathElementIndex::Left
            } else {
                MerklePathElementIndex::Right
            },
        });
    }
    merkle_path
}

// -- Owner key pair --

/// Wrapper around a Grumpkin key pair for NFT ownership.
///
/// Grumpkin coords fit a single `Fr` each (the embedded curve's base
/// field is BN254's scalar field), and the in-circuit Schnorr verify
/// is a native foreign-call gate -- the per-SU constraint is ~6k
/// gates, vs ~47k for the secp256k1 ECDSA scheme this replaces.
#[derive(Debug, Clone, Copy)]
pub struct Owner {
    pub key: GrumpkinKey,
}

impl Owner {
    pub fn generate(_rng: &mut OsRng) -> Self {
        Self {
            key: pso_integrations_shared::witness::random_grumpkin_key()
                .expect("random Grumpkin key"),
        }
    }
}

// -- Worldwide day epoch --

/// Epoch for worldwide day computation (2021-01-01).
fn wwd_epoch() -> anyhow::Result<NaiveDate> {
    NaiveDate::from_ymd_opt(2021, 1, 1).ok_or_else(|| anyhow!("Cannot construct epoch date"))
}

/// Convert a NaiveDate to worldwide day count (days since epoch).
fn worldwide_day_count(date: &NaiveDate) -> anyhow::Result<u64> {
    let epoch = wwd_epoch()?;
    Ok((*date - epoch).num_days() as u64)
}

// -- TributeDraft --

/// Domain-specific NFT representing a tribute draft.
///
/// The `id` is formed as `Poseidon2(owner, worldwide_day)`.
/// The `owner` field is the pre-computed ownership hash (Poseidon5 of public key + nonce).
#[derive(Debug, Serialize, Deserialize)]
pub struct TributeDraft {
    /// Entity ID: `Poseidon2(owner, worldwide_day_count)`
    #[serde(with = "serde_helpers::fr_base58")]
    pub id: Fr,
    /// Ownership hash: `Poseidon5(pk_x_lo, pk_x_hi, pk_y_lo, pk_y_hi, nonce)`
    #[serde(rename = "ownership", with = "serde_helpers::fr_base58")]
    pub owner: Fr,
    /// ISO 4217 currency
    pub currency: Currency,
    /// Amount integer part
    #[serde(with = "serde_helpers::u64_string")]
    pub amount_base: u64,
    /// Amount fractional part
    #[serde(with = "serde_helpers::u64_string")]
    pub amount_atto: u64,
    /// Date for worldwide day computation
    #[serde(with = "serde_helpers::naive_date_yyyymmdd")]
    pub worldwide_day: NaiveDate,
    /// Spending unit IDs included in this tribute draft
    #[serde(with = "serde_helpers::fr_vec_base58")]
    pub su_ids: Vec<Fr>,
}

impl Generated for TributeDraft {
    fn generate(rng: &mut OsRng) -> anyhow::Result<GeneratedNFTData<TributeDraft>> {
        let owner = Owner::generate(rng);
        TributeDraft::generate_with_owner(owner, rng)
    }
}

impl OwnerGenerated for TributeDraft {
    fn generate_with_owner(
        owner: Owner,
        rng: &mut OsRng,
    ) -> anyhow::Result<GeneratedNFTData<Self>> {
        let days_shift = rng.gen_range(1..7);
        let worldwide_day = Utc::now().date_naive() - TimeDelta::days(days_shift as i64);
        let currency = Currency::EUR;
        let amount_base: u64 = rng.gen_range(250..2000);
        let amount_atto: u64 = 0;

        let number_of_su_ids: usize = rng.gen_range(2..10);
        let su_ids: Vec<Fr> = (0..number_of_su_ids).map(|_| Fr::rand(&mut *rng)).collect();

        let nonce = Fr::rand(rng);
        let ownership = ownership_from_grumpkin_key(&owner.key, nonce)?;

        let wwd = worldwide_day_count(&worldwide_day)?;
        let id = compute_tribute_draft_id(&ownership, &Fr::from(wwd))?;

        let nft = TributeDraft {
            id,
            owner: ownership,
            currency,
            amount_base,
            amount_atto,
            worldwide_day,
            su_ids,
        };

        Ok(GeneratedNFTData {
            nft,
            owner_keys: owner,
            nonce,
        })
    }
}

impl OwnableNFT for TributeDraft {
    fn ownership(&self) -> Fr {
        self.owner
    }
}

impl HashableNFT for TributeDraft {
    fn hash(&self) -> Result<Fr, pso_protocol::ProtocolError> {
        compute_tribute_draft_hash(
            &self.id,
            self.currency.numeric(),
            self.amount_base,
            self.amount_atto,
            &self.su_ids,
        )
    }
}

// -- SpendingUnit --

/// Domain-specific NFT representing a spending unit.
///
/// The `id` is completely random.
/// The `owner` field is the pre-computed ownership hash (Poseidon5 of public key + nonce).
#[derive(Debug, Serialize, Deserialize)]
pub struct SpendingUnit {
    /// Random unique identifier
    #[serde(with = "serde_helpers::fr_base58")]
    pub id: Fr,
    /// Ownership hash: `Poseidon5(pk_x_lo, pk_x_hi, pk_y_lo, pk_y_hi, nonce)`
    #[serde(rename = "ownership", with = "serde_helpers::fr_base58")]
    pub owner: Fr,
    /// ISO 4217 currency
    pub currency: Currency,
    /// Amount integer part
    #[serde(with = "serde_helpers::u64_string")]
    pub amount_base: u64,
    /// Amount fractional part
    #[serde(with = "serde_helpers::u64_string")]
    pub amount_atto: u64,
    /// Date for worldwide day computation
    #[serde(with = "serde_helpers::naive_date_yyyymmdd")]
    pub worldwide_day: NaiveDate,
    /// Fingerprints of spending records
    #[serde(with = "serde_helpers::fr_vec_base58")]
    pub spending_records_fingerprints: Vec<Fr>,
    /// Fingerprints of amendment records
    #[serde(with = "serde_helpers::fr_vec_base58")]
    pub amendment_records_fingerprints: Vec<Fr>,
}

impl Generated for SpendingUnit {
    fn generate(rng: &mut OsRng) -> anyhow::Result<GeneratedNFTData<SpendingUnit>> {
        let owner = Owner::generate(rng);
        SpendingUnit::generate_with_owner(owner, rng)
    }
}

impl OwnerGenerated for SpendingUnit {
    fn generate_with_owner(
        owner: Owner,
        rng: &mut OsRng,
    ) -> anyhow::Result<GeneratedNFTData<Self>> {
        let days_shift = rng.gen_range(1..7);
        let worldwide_day = Utc::now().date_naive() - TimeDelta::days(days_shift as i64);
        let currency = Currency::EUR;
        let amount_base: u64 = rng.gen_range(10..500);
        let amount_atto: u64 = 0;

        let num_sr: usize = rng.gen_range(1..5);
        let spending_records_fingerprints: Vec<Fr> =
            (0..num_sr).map(|_| Fr::rand(&mut *rng)).collect();

        let num_ar: usize = rng.gen_range(0..3);
        let amendment_records_fingerprints: Vec<Fr> =
            (0..num_ar).map(|_| Fr::rand(&mut *rng)).collect();

        let nonce = Fr::rand(&mut *rng);
        let ownership = ownership_from_grumpkin_key(&owner.key, nonce)?;

        let id = Fr::rand(&mut *rng);

        let nft = SpendingUnit {
            id,
            owner: ownership,
            currency,
            amount_base,
            amount_atto,
            worldwide_day,
            spending_records_fingerprints,
            amendment_records_fingerprints,
        };

        Ok(GeneratedNFTData {
            nft,
            owner_keys: owner,
            nonce,
        })
    }
}

impl OwnableNFT for SpendingUnit {
    fn ownership(&self) -> Fr {
        self.owner
    }
}

impl HashableNFT for SpendingUnit {
    fn hash(&self) -> Result<Fr, pso_protocol::ProtocolError> {
        let wwd = worldwide_day_count(&self.worldwide_day)
            .map_err(|e| pso_protocol::ProtocolError::Poseidon(e.to_string()))?;
        compute_spending_unit_hash(
            &self.id,
            &self.owner,
            &Fr::from(wwd),
            self.currency.numeric(),
            self.amount_base,
            self.amount_atto,
            &self.spending_records_fingerprints,
            &self.amendment_records_fingerprints,
        )
    }
}

// -- Serde helpers --

mod serde_helpers {
    use super::fr_to_le32;
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use chrono::NaiveDate;
    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serialize/deserialize a single `Fr` as base58-encoded little-endian bytes.
    pub mod fr_base58 {
        use super::*;

        pub fn serialize<S>(fr: &Fr, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = fr_to_le32(fr);
            serializer.serialize_str(&bs58::encode(bytes).into_string())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Fr, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let bytes = bs58::decode(&s)
                .into_vec()
                .map_err(serde::de::Error::custom)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("Fr must be 32 bytes"))?;
            Ok(Fr::from_le_bytes_mod_order(&arr))
        }
    }

    /// Serialize/deserialize `Vec<Fr>` as an array of base58-encoded strings.
    pub mod fr_vec_base58 {
        use super::*;
        use serde::ser::SerializeSeq;

        pub fn serialize<S>(vec: &[Fr], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq = serializer.serialize_seq(Some(vec.len()))?;
            for fr in vec {
                let bytes = fr_to_le32(fr);
                seq.serialize_element(&bs58::encode(bytes).into_string())?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Fr>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let strings: Vec<String> = Vec::deserialize(deserializer)?;
            strings
                .into_iter()
                .map(|s| {
                    let bytes = bs58::decode(&s)
                        .into_vec()
                        .map_err(serde::de::Error::custom)?;
                    let arr: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| serde::de::Error::custom("Fr must be 32 bytes"))?;
                    Ok(Fr::from_le_bytes_mod_order(&arr))
                })
                .collect()
        }
    }

    /// Serialize/deserialize `u64` as a decimal string.
    pub mod u64_string {
        use super::*;

        pub fn serialize<S>(val: &u64, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&val.to_string())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            s.parse::<u64>().map_err(serde::de::Error::custom)
        }
    }

    /// Serialize/deserialize `NaiveDate` as YYYYMMDD numeric (e.g., 20260305).
    pub mod naive_date_yyyymmdd {
        use super::*;

        pub fn serialize<S>(date: &NaiveDate, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let numeric = date.year() as u32 * 10000 + date.month() * 100 + date.day();
            serializer.serialize_u32(numeric)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<NaiveDate, D::Error>
        where
            D: Deserializer<'de>,
        {
            let numeric = u32::deserialize(deserializer)?;
            let year = (numeric / 10000) as i32;
            let month = (numeric % 10000) / 100;
            let day = numeric % 100;
            NaiveDate::from_ymd_opt(year, month, day)
                .ok_or_else(|| serde::de::Error::custom(format!("invalid date: {numeric}")))
        }

        use chrono::Datelike;
    }
}

// -- Hash computation --

mod compute_inputs {
    //! Thin wrappers that delegate to `pso_protocol::nft::*`. The
    //! consensus-binding formulas live in `pso-protocol`; these
    //! functions exist for backward-compatible call sites inside this
    //! crate. Each wrapper converts the `u64`/`Fr` argument shape the
    //! original API used into the shape `pso_protocol::nft` exposes.
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use pso_protocol::ProtocolError;

    /// Compute TributeDraft ID: `Poseidon2(owner, wwd)`. Delegates to
    /// `pso_protocol::nft::compute_tribute_draft_id`.
    pub fn compute_tribute_draft_id(owner: &Fr, wwd: &Fr) -> Result<Fr, ProtocolError> {
        let wwd_u64 = fr_to_u64(wwd)?;
        pso_protocol::nft::compute_tribute_draft_id(owner, wwd_u64)
    }

    /// Compute TributeDraft hash. Delegates to
    /// `pso_protocol::nft::compute_tribute_draft_hash`.
    pub fn compute_tribute_draft_hash(
        id: &Fr,
        currency_numeric: u16,
        amount_base: u64,
        amount_atto: u64,
        su_ids: &[Fr],
    ) -> Result<Fr, ProtocolError> {
        pso_protocol::nft::compute_tribute_draft_hash(
            id,
            currency_numeric,
            amount_base,
            amount_atto,
            su_ids,
        )
    }

    /// Compute SpendingUnit hash. Delegates to
    /// `pso_protocol::nft::compute_spending_unit_hash`.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_spending_unit_hash(
        id: &Fr,
        owner: &Fr,
        wwd: &Fr,
        currency_numeric: u16,
        amount_base: u64,
        amount_atto: u64,
        sr_fingerprints: &[Fr],
        ar_fingerprints: &[Fr],
    ) -> Result<Fr, ProtocolError> {
        let wwd_u64 = fr_to_u64(wwd)?;
        pso_protocol::nft::compute_spending_unit_hash(
            id,
            owner,
            wwd_u64,
            currency_numeric,
            amount_base,
            amount_atto,
            sr_fingerprints,
            ar_fingerprints,
        )
    }

    /// Convert an `Fr` that is known to fit in a `u64` (worldwide day
    /// count) into that `u64`. `pso_protocol::nft::*` takes `u64`
    /// directly; callers in this crate still produce `Fr::from(wwd)`,
    /// so we round-trip here. Returns `InvalidInputLength` if the value
    /// doesn't fit in 8 bytes — only happens for truly bogus inputs.
    fn fr_to_u64(fr: &Fr) -> Result<u64, ProtocolError> {
        let le = fr.into_bigint().to_bytes_le();
        // Reject any high bytes — the input must fit in u64.
        if le.iter().skip(8).any(|b| *b != 0) {
            return Err(ProtocolError::InvalidInputLength {
                expected: 8,
                actual: le.len(),
            });
        }
        let mut buf = [0u8; 8];
        let n = le.len().min(8);
        buf[..n].copy_from_slice(&le[..n]);
        Ok(u64::from_le_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pso_integrations_shared::witness::{
        build_full_proof_witness, build_ownership_witness, FullProofWitnessCtx, OwnershipWitnessCtx,
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_tribute_draft_full_proof_witness() {
        let mut rng = OsRng;
        let data = TributeDraft::generate(&mut rng).unwrap();
        let merkle_path = generate_test_merkle_path(&mut rng);

        let witness = build_full_proof_witness(
            &data.nft,
            FullProofWitnessCtx {
                key: &data.owner_keys.key,
                nonce: data.nonce,
                merkle_path: &merkle_path,
            },
        )
        .unwrap();

        assert_eq!(witness.public_inputs.ownership.nft_hash.len(), 32);
        assert_eq!(witness.public_inputs.merkle_root.len(), 32);
    }

    #[test]
    fn test_tribute_draft_ownership_witness() {
        let mut rng = OsRng;
        let data = TributeDraft::generate(&mut rng).unwrap();

        let nft_hash = data.nft.hash().expect("nft hash");
        let witness = build_ownership_witness(
            &data.nft,
            OwnershipWitnessCtx {
                key: &data.owner_keys.key,
                nonce: data.nonce,
                nft_hash,
            },
        )
        .unwrap();

        assert_eq!(witness.public_inputs.ownership.len(), 32);
        assert_eq!(witness.public_inputs.signature.len(), 64);
    }

    #[test]
    fn test_tribute_draft_hash_deterministic() {
        let mut rng = OsRng;
        let data = TributeDraft::generate(&mut rng).unwrap();

        let hash1 = data.nft.hash().unwrap();
        let hash2 = data.nft.hash().unwrap();

        assert_eq!(hash1, hash2, "TributeDraft hash must be deterministic");
    }

    #[test]
    fn test_spending_unit_full_proof_witness() {
        let mut rng = OsRng;
        let data = SpendingUnit::generate(&mut rng).unwrap();
        let merkle_path = generate_test_merkle_path(&mut rng);

        let witness = build_full_proof_witness(
            &data.nft,
            FullProofWitnessCtx {
                key: &data.owner_keys.key,
                nonce: data.nonce,
                merkle_path: &merkle_path,
            },
        )
        .unwrap();

        assert_eq!(witness.public_inputs.ownership.nft_hash.len(), 32);
        assert_eq!(witness.public_inputs.merkle_root.len(), 32);
    }

    #[test]
    fn test_spending_unit_ownership_witness() {
        let mut rng = OsRng;
        let data = SpendingUnit::generate(&mut rng).unwrap();

        let nft_hash = data.nft.hash().expect("nft hash");
        let witness = build_ownership_witness(
            &data.nft,
            OwnershipWitnessCtx {
                key: &data.owner_keys.key,
                nonce: data.nonce,
                nft_hash,
            },
        )
        .unwrap();

        assert_eq!(witness.public_inputs.ownership.len(), 32);
        assert_eq!(witness.public_inputs.signature.len(), 64);
    }

    #[test]
    fn test_spending_unit_hash_deterministic() {
        let mut rng = OsRng;
        let data = SpendingUnit::generate(&mut rng).unwrap();

        let hash1 = data.nft.hash().unwrap();
        let hash2 = data.nft.hash().unwrap();

        assert_eq!(hash1, hash2, "SpendingUnit hash must be deterministic");
    }

    #[test]
    fn test_tribute_draft_serde_roundtrip() {
        let mut rng = OsRng;
        let data = TributeDraft::generate(&mut rng).unwrap();

        let json = serde_json::to_string(&data.nft).unwrap();
        let deserialized: TributeDraft = serde_json::from_str(&json).unwrap();

        assert_eq!(data.nft.id, deserialized.id);
        assert_eq!(data.nft.owner, deserialized.owner);
        assert_eq!(
            data.nft.currency,
            deserialized.currency
        );
        assert_eq!(
            data.nft.amount_base,
            deserialized.amount_base
        );
        assert_eq!(
            data.nft.amount_atto,
            deserialized.amount_atto
        );
        assert_eq!(data.nft.worldwide_day, deserialized.worldwide_day);
        assert_eq!(data.nft.su_ids, deserialized.su_ids);
    }

    #[test]
    fn test_spending_unit_serde_roundtrip() {
        let mut rng = OsRng;
        let data = SpendingUnit::generate(&mut rng).unwrap();

        let json = serde_json::to_string(&data.nft).unwrap();
        let deserialized: SpendingUnit = serde_json::from_str(&json).unwrap();

        assert_eq!(data.nft.id, deserialized.id);
        assert_eq!(data.nft.owner, deserialized.owner);
        assert_eq!(
            data.nft.currency,
            deserialized.currency
        );
        assert_eq!(
            data.nft.amount_base,
            deserialized.amount_base
        );
        assert_eq!(
            data.nft.amount_atto,
            deserialized.amount_atto
        );
        assert_eq!(data.nft.worldwide_day, deserialized.worldwide_day);
        assert_eq!(
            data.nft.spending_records_fingerprints,
            deserialized.spending_records_fingerprints
        );
        assert_eq!(
            data.nft.amendment_records_fingerprints,
            deserialized.amendment_records_fingerprints
        );
    }

    #[test]
    fn test_tribute_draft_serde_format() {
        let mut rng = OsRng;
        let data = TributeDraft::generate(&mut rng).unwrap();

        let json_value: serde_json::Value = serde_json::to_value(&data.nft).unwrap();
        let obj = json_value.as_object().unwrap();

        // Check field names
        assert!(obj.contains_key("id"), "missing 'id' field");
        assert!(
            obj.contains_key("ownership"),
            "missing 'ownership' field (renamed from 'owner')"
        );
        assert!(obj.contains_key("currency"), "missing 'currency' field");
        assert!(
            obj.contains_key("amount_base"),
            "missing 'amount_base' field"
        );
        assert!(
            obj.contains_key("amount_atto"),
            "missing 'amount_atto' field"
        );
        assert!(
            obj.contains_key("worldwide_day"),
            "missing 'worldwide_day' field"
        );
        assert!(obj.contains_key("su_ids"), "missing 'su_ids' field");

        // Check field should NOT exist under old name
        assert!(
            !obj.contains_key("owner"),
            "'owner' should be renamed to 'ownership'"
        );

        // Check types
        assert!(obj["id"].is_string(), "id should be base58 string");
        assert!(
            obj["ownership"].is_string(),
            "ownership should be base58 string"
        );
        assert!(
            obj["currency"].is_string(),
            "currency should be ISO3 string"
        );
        assert!(
            obj["amount_base"].is_string(),
            "amount_base should be string"
        );
        assert!(
            obj["amount_atto"].is_string(),
            "amount_atto should be string"
        );
        assert!(
            obj["worldwide_day"].is_number(),
            "worldwide_day should be YYYYMMDD numeric"
        );
        assert!(obj["su_ids"].is_array(), "su_ids should be array");

        // Check worldwide_day is YYYYMMDD format
        let wwd = obj["worldwide_day"].as_u64().unwrap();
        assert!(wwd >= 20210101, "worldwide_day should be >= 20210101");
        assert!(wwd <= 99991231, "worldwide_day should be <= 99991231");
    }
}
