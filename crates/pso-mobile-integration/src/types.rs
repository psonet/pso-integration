//! FFI-boundary types for the mobile ZK proof API.
//!
//! All types use UniFFI-compatible primitives: `Vec<u8>` for field elements,
//! `String` for dates, `u16` for currency codes, `u64` for amounts.

/// Result of computing tribute ownership (no proof, pure hash computation).
///
/// Returned by [`compute_tribute_ownership`](crate::api::compute_tribute_ownership).
/// The `nonce` must be stored by the client and passed back to
/// [`prove_tribute_full`](crate::api::prove_tribute_full) later.
#[derive(uniffi::Record)]
pub struct TributeOwnership {
    /// Random nonce used in ownership hash (32 bytes, little-endian BN254 Fr).
    pub nonce: Vec<u8>,
    /// Ownership hash (32 bytes, little-endian BN254 Fr).
    pub ownership: Vec<u8>,
    /// TributeDraft ID: `Poseidon2(ownership, worldwide_day_count)` (32 bytes).
    pub tribute_draft_id: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct NftKeypair {
    /// raw field bytes
    pub sk: Vec<u8>,
    /// sec1 encoded public key in compact form
    pub pk: Vec<u8>,
}

/// A freshly generated Grumpkin keypair for the tribute flow.
///
/// Returned by [`generate_tribute_key`](crate::api::generate_tribute_key).
/// The client stores `secret_key` and passes it back into
/// [`compute_tribute_ownership`](crate::api::compute_tribute_ownership)
/// and the `prove_tribute_*` functions; `public_key` is exposed so the
/// client can display or cross-check the Grumpkin point (the proof
/// functions re-derive it internally, so it never has to be sent back).
#[derive(uniffi::Record)]
pub struct TributeKeypair {
    /// 32-byte Grumpkin secret key, big-endian. Guaranteed to be a
    /// non-zero scalar `< q_Grumpkin`, so it always passes the
    /// `compute_tribute_ownership` / `prove_tribute_*` range gate and
    /// never trips the barretenberg out-of-range abort.
    pub secret_key: Vec<u8>,
    /// 64-byte Grumpkin public key, layout `pk_x_be || pk_y_be` — the
    /// same encoding [`derive_nft_keypair`](crate::api::derive_nft_keypair)
    /// and [`schnorr_verify_grumpkin`](crate::schnorr_verify_grumpkin)
    /// use.
    pub public_key: Vec<u8>,
}

/// Result of generating a ZK proof.
#[derive(Debug, uniffi::Record)]
pub struct ProofResult {
    /// The proof bytes (Barretenberg UltraHonk format).
    pub proof: Vec<u8>,
    /// Public inputs, each as raw bytes.
    pub public_inputs: Vec<Vec<u8>>,
}

/// Input data for a SpendingUnit (received from the SRA server).
#[derive(uniffi::Record)]
pub struct SpendingUnitInput {
    /// Spending unit ID (32 bytes, little-endian BN254 Fr). Server-generated.
    pub id: Vec<u8>,
    /// Nonce for this SU's ownership (32 bytes, little-endian BN254 Fr).
    /// Provided by the server that generated the SU.
    pub nonce: Vec<u8>,
    /// ISO 4217 currency numeric code (e.g., 978 for EUR).
    pub currency: u16,
    /// Amount integer part.
    pub amount_base: u64,
    /// Amount fractional part (atto).
    pub amount_atto: u64,
    /// Worldwide day as "YYYYMMDD" string (e.g., "20260305").
    pub worldwide_day: u32,
    /// Spending record fingerprints, each 32 bytes little-endian.
    pub spending_records_fingerprints: Vec<Vec<u8>>,
    /// Amendment record fingerprints, each 32 bytes little-endian.
    pub amendment_records_fingerprints: Vec<Vec<u8>>,
}

/// Input data for a TributeDraft (client-constructed).
///
/// The `id` and `owner` fields are not included because they are computed:
/// - `owner` = `Poseidon5(pk_x_lo, pk_x_hi, pk_y_lo, pk_y_hi, nonce)`
/// - `id` = `Poseidon2(owner, worldwide_day_count)`
#[derive(uniffi::Record)]
pub struct TributeInput {
    /// ISO 4217 currency numeric code.
    pub currency: u16,
    /// Amount integer part.
    pub amount_base: u64,
    /// Amount fractional part (atto).
    pub amount_atto: u64,
    /// Worldwide day as "YYYYMMDD" string.
    pub worldwide_day: u32,
    /// Spending unit IDs included in this tribute, each 32 bytes little-endian.
    pub su_ids: Vec<Vec<u8>>,
}

/// A single element in a Merkle inclusion path.
#[derive(uniffi::Record)]
pub struct MerklePathElementInput {
    /// Sibling node hash (32 bytes, little-endian BN254 Fr).
    pub node_hash: Vec<u8>,
    /// Position index: 0 = Skip, 1 = Left, 2 = Right.
    pub index: u8,
}

/// One (nonce, derived_owner) pair the wallet is aggregating into a
/// TributeDraft. `derived_owner` matches the value stored at
/// `SpendingUnit.derivedOwner` on-chain (32 bytes, little-endian Fr).
///
/// The aggregation circuit re-derives `Poseidon(pk, nonce)` and
/// asserts it equals `derived_owner` — the wallet provides both
/// because the contract only has `derived_owner` from SU storage and
/// can't re-derive without the secret key.
#[derive(uniffi::Record)]
pub struct SuAggregationSlot {
    /// 32-byte little-endian Fr nonce used at SU mint time.
    pub nonce: Vec<u8>,
    /// 32-byte little-endian Fr -- the value stored at
    /// `SpendingUnit.derivedOwner` for this SU.
    pub derived_owner: Vec<u8>,
    /// 32-byte little-endian Fr -- the SU's entity hash
    /// (`pso_protocol::nft::compute_spending_unit_hash`). The wallet
    /// supplies this because the off-chain prover needs it for the
    /// per-slot binding signature; the on-chain contract independently
    /// reconstructs it from canonical SU storage and zeros the slot if
    /// the SU is missing.
    pub nft_hash: Vec<u8>,
    /// 32-byte raw Grumpkin secret key for this SU. The wallet stores
    /// `shared_sk_hex` per `SuOwnershipWitness` from
    /// `pso-l2-client::wallet`; this is the same value.
    pub grumpkin_sk: Vec<u8>,
}

/// Canonical descriptor for an SU-ownership aggregation circuit tier,
/// returned by [`select_su_aggregation_tier`](crate::api::select_su_aggregation_tier).
///
/// Wallets that aggregate N spending units into a TributeDraft must
/// call the selection function with their actual SU count, then use
/// the returned tier (padding their witness arrays to `tier_n`) and
/// prove against `circuit_hash` / `vk_hash`. This is the single source
/// of truth for tier dispatch across all PSO clients — the on-chain
/// TributeDraft contract resolves through the same table.
#[derive(Debug, uniffi::Record)]
pub struct AggregationTierInfo {
    /// Circuit slot count (1, 2, 4, 6, 8, 16, 32, or 64). Always
    /// `>= n_su` from the caller's request.
    pub tier_n: u32,
    /// Human-readable circuit label (e.g. "pso.su_ownership_aggregation.n4").
    pub label: String,
    /// ACIR `circuit_hash` (32 bytes, big-endian keccak256 of ACIR
    /// bytecode). Matches what the on-chain TributeDraft contract
    /// passes to the `zk_verify` precompile.
    pub circuit_hash: Vec<u8>,
    /// `keccak256(vk_bytes)` for cross-side VK provenance verification
    /// (32 bytes).
    pub vk_hash: Vec<u8>,
}

/// VDF (MinRoot over BLS12-381) computation result.
///
/// Returned by [`compute_vdf`](crate::api::compute_vdf). Both fields are
/// raw byte vectors so they can be attached verbatim to a Users-pool
/// transaction's `vdfOutput` / `vdfProof` fields. The validator
/// re-derives the input from `VdfParams::derive_input_from`, so wallets
/// must use the same canonical construction (see
/// [`derive_vdf_input`](crate::api::derive_vdf_input)).
#[derive(Debug, uniffi::Record)]
pub struct VdfResult {
    /// VDF output `y` — for MinRoot, a 48-byte BLS12-381 Fp element.
    pub output: Vec<u8>,
    /// Wesolowski proof `π` — for MinRoot, a 48-byte BLS12-381 Fp element.
    pub proof: Vec<u8>,
}

/// Snapshot of the VDF parameters compiled into this client.
///
/// Returned by [`vdf_constants`](crate::api::vdf_constants). Wallets
/// surface these to UI so users can see the current calibration; the
/// validator pins the same values at runtime (see
/// `crates/pso-chain/src/config.rs`).
#[derive(Debug, uniffi::Record)]
pub struct VdfConstants {
    /// Base difficulty `T` — sequential MinRoot iterations.
    /// Calibrated for ~2 seconds on iPhone 13 (A15 Bionic).
    pub t_base: u64,
    /// Maximum per-epoch difficulty adjustment in percent (±25%).
    pub max_difficulty_adjustment_pct: u64,
    /// Epoch length in L2 blocks.
    pub epoch_length_blocks: u64,
    /// Backward-looking validity window in blocks (±32 from target).
    pub proof_validity_window: u64,
}

/// Error type for the mobile proof API.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("Invalid secret key: {detail}")]
    InvalidSecretKey { detail: String },

    #[error("Secret key out of range: {detail}")]
    SecretKeyOutOfRange { detail: String },

    #[error("Invalid public key: {detail}")]
    InvalidPublicKey { detail: String },

    #[error("Invalid date format: {detail}")]
    InvalidDate { detail: String },

    #[error("Invalid currency code: {detail}")]
    InvalidCurrency { detail: String },

    #[error("Invalid field element: {detail}")]
    InvalidFieldElement { detail: String },

    #[error("Invalid merkle path element index: {detail}")]
    InvalidMerkleIndex { detail: String },

    #[error("Aggregation tier unavailable: {detail}")]
    AggregationTierUnavailable { detail: String },

    #[error("Invalid VDF input: {detail}")]
    InvalidVdfInput { detail: String },

    #[error("Invalid VDF difficulty: {detail}")]
    InvalidVdfDifficulty { detail: String },

    #[error("Witness generation failed: {detail}")]
    WitnessGenerationFailed { detail: String },

    #[error("Proof generation failed: {detail}")]
    ProofFailed { detail: String },

    #[error("Circuit initialization failed: {detail}")]
    CircuitInitFailed { detail: String },

    #[error("Internal error: {detail}")]
    Internal { detail: String },
}

impl From<pso_integrations_shared::CryptoError> for MobileError {
    fn from(e: pso_integrations_shared::CryptoError) -> Self {
        match e {
            pso_integrations_shared::CryptoError::InvalidSecretKey(s) => {
                MobileError::InvalidSecretKey { detail: s }
            }
            pso_integrations_shared::CryptoError::InvalidPublicKey(s) => {
                MobileError::InvalidPublicKey { detail: s }
            }
            pso_integrations_shared::CryptoError::CryptoOperation(s) => {
                MobileError::Internal { detail: s }
            }
        }
    }
}
