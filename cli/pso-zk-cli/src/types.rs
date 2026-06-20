//! Serializable bridge types for the CLI.
//!
//! Bridge the in-memory domain types (pso-chain-abi entities + PsoV1 key
//! material, none of which are `serde`) and the JSON file workflow of the
//! CLI. Field elements / addresses are hex-encoded; the secret key is
//! hex-encoded.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use alloy_primitives::{Address, B256, U16, U64};
use pso_chain_abi::entity::{SpendingUnit, TributeDraft};

// -- Bridge types --

/// A generated SpendingUnit's body fields (hex / decimal), enough to
/// reconstruct the `pso_chain_abi::entity::SpendingUnit`.
#[derive(Serialize, Deserialize, Clone)]
pub struct SpendingUnitJson {
    /// SU id (32-byte hex).
    pub id: String,
    /// `derivedOwner` (32-byte hex).
    pub derived_owner: String,
    /// Attester address (20-byte hex).
    pub attester: String,
    /// Referrer address (20-byte hex).
    pub referrer: String,
    /// Worldwide day (compact YYYYMMDD).
    pub worldwide_day: u64,
    /// ISO 4217 currency code.
    pub currency: u16,
    /// Amount integer part.
    pub base: u64,
    /// Amount fractional part (atto).
    pub atto: u64,
    /// SR fingerprints (each 32-byte hex).
    pub sr: Vec<String>,
    /// AR fingerprints (each 32-byte hex).
    pub ar: Vec<String>,
}

impl SpendingUnitJson {
    /// Reconstruct the typed entity.
    pub fn into_entity(self) -> Result<SpendingUnit> {
        Ok(SpendingUnit {
            id: b256(&self.id)?,
            derived_owner: b256(&self.derived_owner)?,
            attester: address(&self.attester)?,
            referrer: address(&self.referrer)?,
            worldwide_day: U64::from(self.worldwide_day),
            currency: U16::from(self.currency),
            base: U64::from(self.base),
            atto: U64::from(self.atto),
            sr: self.sr.iter().map(|s| b256(s)).collect::<Result<_>>()?,
            ar: self.ar.iter().map(|s| b256(s)).collect::<Result<_>>()?,
        })
    }
}

/// A generated TributeDraft's body fields.
#[derive(Serialize, Deserialize, Clone)]
pub struct TributeDraftJson {
    /// TD id (32-byte hex).
    pub id: String,
    /// `derivedOwner` (32-byte hex).
    pub derived_owner: String,
    /// Worldwide day (compact YYYYMMDD).
    pub worldwide_day: u64,
    /// ISO 4217 currency code.
    pub currency: u16,
    /// Amount integer part.
    pub base: u64,
    /// Amount fractional part (atto).
    pub atto: u64,
    /// SU ids (each 32-byte hex).
    pub su_ids: Vec<String>,
}

impl TributeDraftJson {
    /// Reconstruct the typed entity.
    pub fn into_entity(self) -> Result<TributeDraft> {
        Ok(TributeDraft {
            id: b256(&self.id)?,
            derived_owner: b256(&self.derived_owner)?,
            worldwide_day: U64::from(self.worldwide_day),
            currency: U16::from(self.currency),
            base: U64::from(self.base),
            atto: U64::from(self.atto),
            su_ids: self.su_ids.iter().map(|s| b256(s)).collect::<Result<_>>()?,
        })
    }
}

/// Output of `nft generate` — saved to JSON.
///
/// Contains the NFT body plus the secret key + nonce required for
/// subsequent proof generation. The secret key is hex-encoded.
///
/// **WARNING**: This file contains a private key. Treat it as sensitive.
#[derive(Serialize, Deserialize)]
pub struct GeneratedOutput {
    /// Prominent warning that the file contains sensitive material.
    #[serde(rename = "WARNING")]
    pub warning: String,
    /// NFT type discriminator ("tribute-draft" or "spending-unit").
    pub nft_type: String,
    /// The SpendingUnit body (present iff `nft_type == "spending-unit"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spending_unit: Option<SpendingUnitJson>,
    /// The TributeDraft body (present iff `nft_type == "tribute-draft"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tribute_draft: Option<TributeDraftJson>,
    /// NFT id (32-byte hex) — the proof's claimed commitment id.
    pub nft_id: String,
    /// `derivedOwner` (32-byte hex).
    pub derived_owner: String,
    /// NFT entity hash (32-byte hex).
    pub nft_hash: String,
    /// Hex-encoded NFT signing secret key (Grumpkin scalar, 32 bytes).
    pub secret_key_hex: String,
    /// Hex-encoded nonce field element (32 bytes, big-endian).
    pub nonce_hex: String,
}

/// Output of `proof generate` — saved to JSON. The proof fields (bb's
/// `Vec<Vec<u8>>` field encoding, one hex string each) + the public
/// inputs in hex, plus circuit metadata. Keeping the field structure
/// (rather than a flat blob) lets `verify` feed bb the exact shape it
/// produced.
#[derive(Serialize, Deserialize)]
pub struct SerializableProof {
    /// Proof fields, each a hex-encoded field element.
    pub proof: Vec<String>,
    /// Hex-encoded public input field elements (each 32-byte big-endian).
    pub public_inputs: Vec<String>,
    /// Proof mode used ("ownership").
    pub mode: String,
    /// Circuit hash for traceability (hex).
    pub circuit_hash: String,
}

// -- Helpers --

fn b256(s: &str) -> Result<B256> {
    let bytes =
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| anyhow!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes, got {}", bytes.len()));
    }
    Ok(B256::from_slice(&bytes))
}

fn address(s: &str) -> Result<Address> {
    let bytes =
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| anyhow!("invalid hex: {e}"))?;
    if bytes.len() != 20 {
        return Err(anyhow!("expected 20 bytes, got {}", bytes.len()));
    }
    Ok(Address::from_slice(&bytes))
}
