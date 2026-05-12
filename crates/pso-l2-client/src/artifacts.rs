//! Serializable artifacts that flow between SRA and Wallet steps.
//!
//! The CLIs pass these around as JSON files; the e2e test crate keeps
//! them in memory as Rust structs. Same shape either way — `serde`
//! derives let both use cases share one declaration.

use serde::{Deserialize, Serialize};

/// One (nonce, derivedOwner) tuple a wallet computed before asking
/// the SRA to mint a SpendingUnit.
///
/// The wallet kept the nonce private; the SRA only saw `derivedOwner`.
/// Bundling `suId` here lets the wallet later assemble several of
/// these into an `AggregationRequest` without having to remember which
/// SU each was for.
///
/// Conceptually this is "Proof of Ownership material" — the wallet's
/// receipt that it can later prove ownership of the SU under its
/// keypair. No ZK proof is produced at this stage; the actual proof
/// comes from `AggregationRequest -> AggregationProofBundle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuOwnershipRecord {
    /// On-chain SU id (uint256, hex string with `0x` prefix).
    pub su_id: String,
    /// 32-byte little-endian BN254 Fr nonce, hex-encoded.
    pub nonce: String,
    /// 32-byte little-endian BN254 Fr `derivedOwner`, hex-encoded.
    pub derived_owner: String,
}

/// Resolved aggregation tier descriptor — what `pso-zk-canonical`
/// reports for a given SU count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationTier {
    /// Circuit slot count (1, 2, 4, 6, 8, 16, 32, or 64).
    pub tier_n: u32,
    /// Human-readable circuit label.
    pub label: String,
    /// ACIR circuit hash, hex-encoded big-endian keccak256.
    pub circuit_hash: String,
}

/// Aggregation proof + the public inputs the on-chain TributeDraft
/// contract will compare against. Produced by
/// `pso_l2_client::wallet::aggregate_ownership`. Submitted to
/// `TributeDraft.submit` as the `aggregationProof` calldata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationProofBundle {
    /// TributeDraft id the proof is bound to.
    pub tribute_draft_id: String,
    /// Wallet's pre-computed TD-level `derivedOwner` commitment
    /// (Poseidon5 over the wallet pubkey + TD nonce).
    pub td_derived_owner: String,
    /// SU ids the proof aggregates over, in the order the wallet
    /// declared. Length ≤ `tier.tier_n`.
    pub su_ids: Vec<String>,
    /// Resolved tier the proof was generated against.
    pub tier: AggregationTier,
    /// Raw `aggregationProof` bytes to pass into
    /// `TributeDraft.submit`. Already in the format the on-chain
    /// `zk_verify` precompile expects (length-prefixed public inputs
    /// followed by the proof body).
    pub proof_bytes_hex: String,
}

/// Full proof artifact — ownership + Merkle inclusion against a TD's
/// canonical commitment. Produced after the TD has been minted.
/// Not yet consumed by any on-chain flow; emitted as JSON for the
/// wallet to retain for later redemption / audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullProofBundle {
    /// TributeDraft id the proof attests.
    pub tribute_draft_id: String,
    /// Circuit label (`pso.full_proof`).
    pub circuit_label: String,
    /// Public inputs of the produced proof, each 32 bytes hex.
    pub public_inputs: Vec<String>,
    /// Raw proof bytes hex (no length prefix).
    pub proof_bytes_hex: String,
}
