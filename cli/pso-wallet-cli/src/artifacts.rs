//! Serializable artifacts that flow between wallet CLI steps.
//!
//! The mobile FFI's records (`IssuanceReport`, `NftOwnershipWitness`,
//! `AggregationProofResult`) are not `serde`-derived, so the CLI keeps
//! hex-encoded JSON shadows that round-trip them across `prepare-su` →
//! `aggregate` → `submit-td`.

use eyre::Result;
use serde::{Deserialize, Serialize};

/// The issuance report the SRA hands the wallet (hex-encoded fields).
/// Input to `prepare-su`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceReportJson {
    /// NFT id (32-byte hex).
    pub nft_id: String,
    /// `derivedOwner` (32-byte hex).
    pub derived_owner: String,
    /// NFT entity hash (32-byte hex).
    pub nft_hash: String,
    /// Opaque transcript for signer reconstruction (32-byte hex).
    pub opaque_pk: String,
    /// Ownership nonce (32-byte hex).
    pub nonce: String,
}

impl IssuanceReportJson {
    /// Lower into the mobile FFI's `IssuanceReport`.
    pub fn into_ffi(self) -> Result<pso_mobile_integration::IssuanceReport> {
        Ok(pso_mobile_integration::IssuanceReport {
            nft_id: hex_vec(&self.nft_id)?,
            derived_owner: hex_vec(&self.derived_owner)?,
            nft_hash: hex_vec(&self.nft_hash)?,
            opaque_pk: hex_vec(&self.opaque_pk)?,
            nonce: hex_vec(&self.nonce)?,
        })
    }
}

/// One ownership witness produced by `prepare-su`, consumed by
/// `aggregate`. Hex-encoded shadow of the FFI's `NftOwnershipWitness`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipWitnessJson {
    /// Signing pk x (32-byte hex).
    pub pk_x: String,
    /// Signing pk y (32-byte hex).
    pub pk_y: String,
    /// 64-byte `s ‖ e` signature (hex).
    pub signature: String,
    /// Ownership nonce (32-byte hex).
    pub nonce: String,
    /// `derivedOwner` (32-byte hex).
    pub derived_owner: String,
    /// NFT entity hash (32-byte hex).
    pub nft_hash: String,
    /// Submission binding the signature commits to (32-byte hex).
    pub binding: String,
}

impl OwnershipWitnessJson {
    /// Lift the FFI witness into the JSON shadow.
    pub fn from_ffi(w: &pso_mobile_integration::NftOwnershipWitness) -> Self {
        Self {
            pk_x: hex_str(&w.pk_x),
            pk_y: hex_str(&w.pk_y),
            signature: hex_str(&w.signature),
            nonce: hex_str(&w.nonce),
            derived_owner: hex_str(&w.derived_owner),
            nft_hash: hex_str(&w.nft_hash),
            binding: hex_str(&w.binding),
        }
    }

    /// Lower into the FFI witness for aggregation.
    pub fn into_ffi(self) -> Result<pso_mobile_integration::NftOwnershipWitness> {
        Ok(pso_mobile_integration::NftOwnershipWitness {
            pk_x: hex_vec(&self.pk_x)?,
            pk_y: hex_vec(&self.pk_y)?,
            signature: hex_vec(&self.signature)?,
            nonce: hex_vec(&self.nonce)?,
            derived_owner: hex_vec(&self.derived_owner)?,
            nft_hash: hex_vec(&self.nft_hash)?,
            binding: hex_vec(&self.binding)?,
        })
    }
}

/// The aggregation proof bundle `aggregate` writes and `submit-td`
/// reads. Carries the proof bytes + the canonical circuit identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationBundleJson {
    /// Slot capacity of the chosen tier (1/2/4/8/16/32/64).
    pub tier_n: u32,
    /// `keccak256(acir)` circuit identity (32-byte hex).
    pub circuit_hash: String,
    /// `keccak256(vk)` (32-byte hex).
    pub vk_hash: String,
    /// Proof bytes (hex).
    pub proof: String,
    /// Public inputs (`2N + 1`), each 32-byte hex.
    pub public_inputs: Vec<String>,
}

impl AggregationBundleJson {
    /// Lift the FFI aggregation result into the JSON bundle.
    pub fn from_ffi(r: &pso_mobile_integration::AggregationProofResult) -> Self {
        Self {
            tier_n: r.tier_n,
            circuit_hash: hex_str(&r.circuit_hash),
            vk_hash: hex_str(&r.vk_hash),
            proof: hex_str(&r.proof),
            public_inputs: r.public_inputs.iter().map(|p| hex_str(p)).collect(),
        }
    }
}

fn hex_str(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_vec(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
}
