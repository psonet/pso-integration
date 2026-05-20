//! Wallet-side flow per the privacy-preserving L2 architecture spec.
//!
//! ## Two phases
//!
//! **Phase 1 — Submit TributeDraft on L2.** Wallet runs App. A per
//! SU, assembles the per-SU material (Grumpkin sk, nonce,
//! derivedOwner, SU entity hash), and produces a single
//! flat-aggregation proof via [`prove_su_aggregation`]. The chosen
//! tier circuit duplicates the per-SU ownership constraint set
//! inline -- no recursive proof verification. Calls
//! `TributeDraft.submit(...)` with the bundle.
//!
//! **Phase 2 — Post-mint TD ownership proof.** Wallet generates a
//! separate ownership proof over the minted TD using a fresh per-TD
//! Grumpkin keypair. The proof is **not** consumed by L2; it's a
//! wallet-local artifact for later L1-redemption tooling.
//!
//! ## What's implemented
//!
//! - [`derive_shared_key`] — App. A shared-key reconstruction
//!   (`pso-l2-client::shared_key` module).
//! - [`prepare_su_ownership_material`] — wallet-side counterpart to
//!   the SRA receipt: turns `(consent_sk, pk_cu, su_nonce)` into the
//!   Grumpkin signing material needed to prove ownership of one SU.
//! - [`SuOwnershipWitness`], [`SuAggregationInput`],
//!   [`AggregationProofBundle`] — the data shape every flow function
//!   operates on.
//! - [`prove_su_aggregation`] — drives the flat-aggregation prove
//!   call end-to-end against the canonical
//!   `FLAT_AGGREGATION_N{N}` VK. Single prove pass; no per-SU
//!   intermediate proofs.
//! - [`submit_tribute_draft`] — broadcasts the bundle's proof bytes
//!   on L2 via the existing `TributeDraft.submit` ABI. Goes live
//!   once the contract switches its `zk_verify` lookup to
//!   `FLAT_AGGREGATION_N*` (pso-chain side, separate workstream).

use alloy::primitives::{Bytes, FixedBytes, TxHash, U256};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use k256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use pso_integrations_shared::witness::{derive_grumpkin_public_key, fr_to_le32, GrumpkinKey};

use crate::abi::{ITributeDraft, TRIBUTE_DRAFT};
use crate::artifacts::{AggregationProofBundle, AggregationTier};
use crate::client::L2Client;
use crate::error::L2ClientError;
use crate::shared_key::{derive_shared_key, SharedKey};

// =====================================================================
// Phase 1, step A — derive (shared_sk, shared_pk, owner) for one SU.
// =====================================================================

/// Everything the wallet needs to know to prove ownership of one SU.
///
/// Produced by [`prepare_su_ownership_material`] from the wallet's
/// `consent_sk` plus the receipt the SRA delivered out-of-band.
/// Persisted between SRA-mint and TributeDraft-aggregation phases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuOwnershipWitness {
    /// On-chain SU id (32-byte uint256, big-endian hex).
    pub su_id: String,
    /// 32-byte LE Fr nonce used during owner derivation.
    pub su_nonce_le_hex: String,
    /// 32-byte LE Fr `derivedOwner` value -- matches the SU's
    /// on-chain `derivedOwner` field. The wallet stores this so it
    /// doesn't have to re-derive at proving time, and so a corrupted
    /// shared key surfaces immediately (mismatch with the on-chain
    /// value).
    pub derived_owner_le_hex: String,
    /// Grumpkin public-key x coordinate, 32-byte LE Fr hex. (Was a
    /// SEC1-compressed secp256k1 pubkey in the pre-Schnorr design.)
    pub shared_pk_x_le_hex: String,
    /// Grumpkin public-key y coordinate, 32-byte LE Fr hex.
    pub shared_pk_y_le_hex: String,
    /// 32-byte raw Grumpkin secret-key bytes. **Sensitive.** Persist
    /// in keystore only -- never write to plain disk. This is the
    /// signing key the in-circuit Schnorr verification cares about;
    /// leak ⇒ anyone holding it can claim the SU.
    pub shared_sk_hex: String,
}

impl SuOwnershipWitness {
    /// Reconstruct the Grumpkin key from the persisted hex fields.
    pub fn grumpkin_key(&self) -> Result<GrumpkinKey, L2ClientError> {
        let sk_vec = hex_to_vec(&self.shared_sk_hex)?;
        if sk_vec.len() != 32 {
            return Err(L2ClientError::InvalidInput(format!(
                "shared_sk_hex must be 32 bytes, got {}",
                sk_vec.len()
            )));
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&sk_vec);
        derive_grumpkin_public_key(&sk_bytes)
            .map_err(|e| L2ClientError::Witness(format!("derive grumpkin pk: {e}")))
    }
}

/// Run App. A and produce the [`SuOwnershipWitness`] for one SU.
///
/// `consent_sk` is the user's per-wallet consent key (long-lived).
/// `pk_cu` is the SRA's per-SU ephemeral public key, delivered in
/// the receipt. `su_nonce` is the 32-byte nonce extracted from the
/// decrypted `encrypted_report` (also in the receipt). `su_id` is
/// the on-chain SU id.
///
/// The output `derived_owner` should match the SU's on-chain
/// `derivedOwner` field. Mismatch means either a receipt mix-up or
/// SRA misbehaviour — the caller should compare.
pub fn prepare_su_ownership_material(
    consent_sk: &SecretKey,
    pk_cu: &PublicKey,
    su_nonce: [u8; 32],
    su_id: U256,
) -> Result<SuOwnershipWitness, L2ClientError> {
    // App. A: secp256k1 ECDH + HKDF lands a 32-byte secret (`shared_sk_bytes`).
    // Off-chain ECDH stays on secp256k1 for wallet interop; the
    // resulting 32-byte scalar is reinterpreted as a Grumpkin scalar
    // for the in-circuit Schnorr signing path. Reduce mod
    // `q_Grumpkin` before handing to barretenberg — bb 5.x's
    // `schnorr_compute_public_key` throws an uncatchable C++
    // exception for inputs >= q.
    let SharedKey { secret, public: _ } = derive_shared_key(consent_sk, pk_cu, &su_nonce)?;
    let sk_raw: [u8; 32] = secret.to_bytes().into();
    let sk_bytes = pso_integrations_shared::witness::reduce_to_grumpkin_sk(&sk_raw);
    let grumpkin = derive_grumpkin_public_key(&sk_bytes)
        .map_err(|e| L2ClientError::Witness(format!("derive grumpkin pk: {e}")))?;

    // The `su_nonce` is a 32-byte LE-encoded BN254 Fr.
    let nonce_fr = Fr::from_le_bytes_mod_order(&su_nonce);
    let owner_fr =
        pso_protocol::ownership::compute_ownership_grumpkin(grumpkin.pk_x, grumpkin.pk_y, nonce_fr)
            .map_err(|e| L2ClientError::Witness(format!("compute_ownership: {e}")))?;

    Ok(SuOwnershipWitness {
        su_id: format!("0x{:064x}", su_id),
        su_nonce_le_hex: format!("0x{}", hex::encode(su_nonce)),
        derived_owner_le_hex: format!("0x{}", hex::encode(fr_to_le32(&owner_fr))),
        shared_pk_x_le_hex: format!("0x{}", hex::encode(fr_to_le32(&grumpkin.pk_x))),
        shared_pk_y_le_hex: format!("0x{}", hex::encode(fr_to_le32(&grumpkin.pk_y))),
        shared_sk_hex: format!("0x{}", hex::encode(sk_bytes)),
    })
}

// =====================================================================
// Phase 1, step B — prove SU ownership (one inner proof per SU).
// =====================================================================

/// Per-SU input bundle for [`prove_su_aggregation`]. The wallet
/// assembles one of these per Spending Unit it's aggregating into a
/// Tribute Draft, drawing from material it persisted after
/// [`prepare_su_ownership_material`] plus the SU hash recomputed via
/// `pso_protocol::nft::compute_spending_unit_hash` (or from the
/// canonical on-chain state via the SU hash precompile).
#[derive(Debug, Clone)]
pub struct SuAggregationInput {
    /// On-chain SU id, hex-encoded `0x` + 32-byte big-endian uint256.
    pub su_id: String,
    /// Grumpkin secret-key bytes for this SU (= `shared_sk_hex` from
    /// the persisted [`SuOwnershipWitness`]).
    pub grumpkin_sk: [u8; 32],
    /// SU nonce as a BN254 Fr.
    pub nonce: Fr,
    /// SU `derivedOwner` as a BN254 Fr.
    pub derived_owner: Fr,
    /// SU entity hash (`compute_spending_unit_hash`) as a BN254 Fr.
    pub nft_hash: Fr,
}

// =====================================================================
// Phase 1, step B+C -- prove all N SUs in a single flat-aggregation
// circuit pass. No per-SU intermediate proofs; the per-SU constraint
// set is duplicated inline inside the chosen tier circuit.
// =====================================================================

/// Build the flat-aggregation proof the wallet submits to
/// `TributeDraft.submit` as the `aggregationProof` calldata.
///
/// Picks the smallest canonical tier `>= inputs.len()`, builds the
/// witness via
/// [`pso_integrations_shared::witness::build_flat_aggregation_witness`]
/// (zero-padding unused slots), loads the tier bytecode from
/// `pso-zk-circuit-noir`'s embedded data, and calls
/// `pso_zk_circuit_noir::prove_ultra_honk_keccak` against the canonical
/// `FLAT_AGGREGATION_N{N}` VK.
///
/// The returned [`AggregationProofBundle`] is ready for
/// [`submit_tribute_draft`].
pub fn prove_su_aggregation(
    inputs: &[SuAggregationInput],
    tribute_draft_id: U256,
    td_derived_owner: Fr,
) -> Result<AggregationProofBundle, L2ClientError> {
    use pso_integrations_shared::witness::{
        build_flat_aggregation_witness, derive_grumpkin_public_key, FlatAggregationSlot,
    };

    if inputs.is_empty() {
        return Err(L2ClientError::InvalidInput(
            "at least one SU input required".into(),
        ));
    }

    let tier_resolved =
        pso_zk_canonical::select_aggregation_tier(inputs.len() as u32).ok_or_else(|| {
            L2ClientError::InvalidInput(format!(
                "no aggregation tier for n_su={} (must be 1..=64)",
                inputs.len()
            ))
        })?;

    // Build slots.
    let mut slots: Vec<FlatAggregationSlot> = Vec::with_capacity(inputs.len());
    for inp in inputs {
        let key = derive_grumpkin_public_key(&inp.grumpkin_sk)
            .map_err(|e| L2ClientError::Witness(format!("grumpkin pk: {e}")))?;
        slots.push(FlatAggregationSlot {
            key,
            nonce: inp.nonce,
            owner: inp.derived_owner,
            nft_hash: inp.nft_hash,
        });
    }

    let witness_vec = build_flat_aggregation_witness(&slots, tier_resolved.tier_n)
        .map_err(|e| L2ClientError::Witness(format!("flat witness: {e}")))?;
    let witness_map = pso_zk_circuit_noir::witness::from_vec_to_witness_map(witness_vec)
        .map_err(|e| L2ClientError::Witness(format!("witness map: {e}")))?;

    // Load the bytecode for this tier from the embedded canonical JSON.
    let bytecode_b64 = flat_aggregation_bytecode_b64(tier_resolved.tier_n)?;
    let _ = pso_zk_circuit_noir::barretenberg::srs::setup_srs_from_bytecode(bytecode_b64, None, true)
        .map_err(|e| L2ClientError::Witness(format!("setup_srs: {e}")))?;
    let proof_bytes = pso_zk_circuit_noir::barretenberg::prove::prove_ultra_honk_keccak(
        bytecode_b64,
        witness_map,
        tier_resolved.descriptor.vk_bytes.to_vec(),
        false, // disable_zk
        false, // low_memory — desktop path; mobile uses its own
        None,
    )
    .map_err(|e| L2ClientError::Witness(format!("prove: {e}")))?;

    // Assemble the bundle the on-chain TributeDraft.submit takes.
    let _ = td_derived_owner; // bound on-chain via TributeDraft's stored `derivedOwner`; carried for clarity here.
    Ok(AggregationProofBundle {
        tribute_draft_id: format!("0x{:064x}", tribute_draft_id),
        td_derived_owner: format!("0x{}", hex::encode(fr_to_le32(&td_derived_owner))),
        su_ids: inputs.iter().map(|i| i.su_id.clone()).collect(),
        tier: AggregationTier {
            tier_n: tier_resolved.tier_n,
            label: tier_resolved.descriptor.label.to_string(),
            circuit_hash: format!("0x{}", hex::encode(tier_resolved.descriptor.circuit_hash)),
        },
        proof_bytes_hex: format!("0x{}", hex::encode(proof_bytes)),
    })
}

/// Return the embedded base64 ACIR bytecode for the chosen
/// flat-aggregation tier. Mirrors the tier dispatch in
/// `pso-mobile-integration::circuits::flat_aggregation_bytecode`,
/// but as a `&'static str` (the noir_rs `setup_srs_from_bytecode`
/// and `prove_ultra_honk_keccak` calls accept the base64 string
/// directly, no JSON parsing needed).
fn flat_aggregation_bytecode_b64(tier_n: u32) -> Result<&'static str, L2ClientError> {
    // Pull the canonical JSON document from pso-zk-circuit-noir's
    // public API (introduced after the prior `include_str!` form
    // proved fragile in CI — it required pso-zk-circuits checked
    // out as a sibling directory). The document is
    // `{"bytecode": "<base64>", "hash": "..."}`; we parse the
    // bytecode field once per tier and cache.
    static N1: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static N2: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static N4: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static N8: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static N16: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static N32: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static N64: std::sync::OnceLock<String> = std::sync::OnceLock::new();

    fn extract_b64(raw: &str) -> Result<String, L2ClientError> {
        let v: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| L2ClientError::InvalidInput(format!("parse circuit json: {e}")))?;
        v.get("bytecode")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .ok_or_else(|| L2ClientError::InvalidInput("missing bytecode field".into()))
    }

    let cell = match tier_n {
        1 => &N1,
        2 => &N2,
        4 => &N4,
        8 => &N8,
        16 => &N16,
        32 => &N32,
        64 => &N64,
        other => {
            return Err(L2ClientError::InvalidInput(format!(
                "no flat-aggregation circuit for tier_n={other}"
            )))
        }
    };
    let s = cell.get_or_init(|| {
        let raw = pso_zk_circuit_noir::flat_aggregation_json(tier_n)
            .expect("tier_n already gated by the match above");
        extract_b64(raw).expect("embedded circuit JSON has a bytecode field")
    });
    Ok(s.as_str())
}

// =====================================================================
// Phase 1, step D — broadcast on L2.
// =====================================================================

/// Submit the TributeDraft on L2 using a previously-built
/// [`AggregationProofBundle`].
///
/// Contract signature unchanged from the current deployment:
///
/// ```solidity
/// TributeDraft.submit(tdId, derivedOwner, suIds, aggregationProof)
/// ```
///
/// What changed is the meaning of `aggregationProof` — it's now the
/// output of the recursion fold, not the flat one-keypair-N-nonces
/// proof the current chain still expects. Until both pso-zk-circuits
/// and pso-chain land their pieces of the redesign, this call will
/// produce a proof the chain rejects.
pub async fn submit_tribute_draft(
    client: &L2Client,
    bundle: &AggregationProofBundle,
) -> Result<TxHash, L2ClientError> {
    let provider = client.write_provider()?;
    let tdid = parse_uint256(&bundle.tribute_draft_id)?;
    let derived_owner = parse_b32(&bundle.td_derived_owner)?;
    let su_ids: Vec<U256> = bundle
        .su_ids
        .iter()
        .map(|s| parse_uint256(s))
        .collect::<Result<_, _>>()?;
    let proof_bytes = parse_hex_bytes(&bundle.proof_bytes_hex)?;

    let inst = ITributeDraft::new(TRIBUTE_DRAFT, provider);
    let pending = inst
        .submit(tdid, derived_owner, su_ids, Bytes::from(proof_bytes))
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .map_err(|e| L2ClientError::Contract(format!("TD submit: {e}")))?;
    Ok(*pending.tx_hash())
}

// =====================================================================
// Phase 2 — post-mint TD ownership proof (wallet-local artifact).
// =====================================================================

/// TD-level Grumpkin keypair + nonce material the wallet rolls
/// before submitting a TributeDraft. The wallet persists this;
/// it's needed in Phase 2 to produce the TD ownership proof for L1
/// redemption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdOwnershipMaterial {
    /// 32-byte raw Grumpkin `td_sk`. **Sensitive.**
    pub td_sk_hex: String,
    /// Grumpkin x coordinate of `td_pk` (32-byte LE Fr hex).
    pub td_pk_x_le_hex: String,
    /// Grumpkin y coordinate of `td_pk` (32-byte LE Fr hex).
    pub td_pk_y_le_hex: String,
    /// 32-byte LE Fr nonce used during owner derivation.
    pub td_nonce_le_hex: String,
    /// 32-byte LE Fr `derivedOwner` value -- what the wallet passes
    /// to `TributeDraft.submit`'s `derivedOwner` argument.
    pub td_derived_owner_le_hex: String,
}

/// Roll a fresh per-TD keypair + nonce and compute `td_derived_owner`.
///
/// The wallet calls this once per TributeDraft before aggregation.
/// The output goes both into the aggregation request (so the
/// recursive proof binds against the same TD owner) and stored
/// locally for Phase 2.
pub fn prepare_td_keypair() -> Result<TdOwnershipMaterial, L2ClientError> {
    let mut sk_raw = [0u8; 32];
    OsRng.fill_bytes(&mut sk_raw);
    // bb 5.x's schnorr_compute_public_key rejects sk >= q_Grumpkin
    // with an uncatchable C++ abort; reduce the random source.
    let sk_bytes = pso_integrations_shared::witness::reduce_to_grumpkin_sk(&sk_raw);
    let td_key = derive_grumpkin_public_key(&sk_bytes)
        .map_err(|e| L2ClientError::Witness(format!("derive grumpkin td pk: {e}")))?;

    let mut nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_fr = Fr::from_le_bytes_mod_order(&nonce_bytes);

    let owner_fr =
        pso_protocol::ownership::compute_ownership_grumpkin(td_key.pk_x, td_key.pk_y, nonce_fr)
            .map_err(|e| L2ClientError::Witness(format!("compute_ownership: {e}")))?;

    Ok(TdOwnershipMaterial {
        td_sk_hex: format!("0x{}", hex::encode(sk_bytes)),
        td_pk_x_le_hex: format!("0x{}", hex::encode(fr_to_le32(&td_key.pk_x))),
        td_pk_y_le_hex: format!("0x{}", hex::encode(fr_to_le32(&td_key.pk_y))),
        td_nonce_le_hex: format!("0x{}", hex::encode(nonce_bytes)),
        td_derived_owner_le_hex: format!("0x{}", hex::encode(fr_to_le32(&owner_fr))),
    })
}

/// TD ownership proof — post-mint artifact for L1 redemption. NOT
/// consumed by L2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdOwnershipProof {
    /// Which TD this proof attests.
    pub tribute_draft_id: String,
    /// `td_derived_owner` (32-byte LE hex).
    pub td_derived_owner_le_hex: String,
    /// `td_hash` per §3.3.3 (32-byte LE hex).
    pub td_hash_le_hex: String,
    /// Raw proof bytes (UltraHonkKeccak).
    pub proof_bytes_hex: String,
}

/// Generate the post-mint TD ownership proof. Same circuit shape as
/// [`prove_su_ownership`] — just different inputs.
///
/// **Not yet implemented at the prover level.** Depends on the same
/// ownership circuit rewrite as [`prove_su_ownership`]; see
/// `docs/aggregation-redesign.md`.
pub fn prove_td_ownership(
    _material: &TdOwnershipMaterial,
    _tribute_draft_id: U256,
    _td_hash: Fr,
) -> Result<TdOwnershipProof, L2ClientError> {
    Err(L2ClientError::CircuitNotAvailable {
        detail: "TD ownership reuses the per-SU ownership circuit (different inputs); \
             waiting on the §4.2-correct circuit in pso-zk-circuits. \
             See docs/aggregation-redesign.md."
            .into(),
    })
}

// =====================================================================
// Helpers
// =====================================================================

fn parse_uint256(s: &str) -> Result<U256, L2ClientError> {
    let bytes = hex_to_vec(s)?;
    if bytes.len() != 32 {
        return Err(L2ClientError::InvalidInput(format!(
            "uint256 hex must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(arr))
}

fn parse_b32(s: &str) -> Result<FixedBytes<32>, L2ClientError> {
    let bytes = hex_to_vec(s)?;
    if bytes.len() != 32 {
        return Err(L2ClientError::InvalidInput(format!(
            "bytes32 hex must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(FixedBytes::from(arr))
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, L2ClientError> {
    hex_to_vec(s)
}

fn hex_to_vec(s: &str) -> Result<Vec<u8>, L2ClientError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| L2ClientError::InvalidInput(format!("hex: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_secret_key() -> SecretKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SecretKey::from_slice(&bytes).unwrap()
    }

    /// Cross-side sanity: wallet runs App. A from its consent_sk and
    /// the SRA's `pk_cu`; SRA's own derivation (from `sk_cu` and the
    /// wallet's `consent_pk`) must produce the same `derivedOwner`
    /// the wallet sees. Tests the spec's "same shared key on both
    /// sides → same Poseidon owner" property.
    #[test]
    fn prepare_su_ownership_material_matches_sra_side() {
        let consent_sk = random_secret_key();
        let sra_ephemeral_sk = random_secret_key();
        let mut su_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut su_nonce);
        let su_id = U256::from(42u64);

        let witness = prepare_su_ownership_material(
            &consent_sk,
            &sra_ephemeral_sk.public_key(),
            su_nonce,
            su_id,
        )
        .unwrap();

        // SRA side: derive the same 32-byte shared secret from its
        // own ephemeral_sk + the wallet's consent_pk, then reinterpret
        // as a Grumpkin scalar and compute the same owner.
        let sra_side = crate::shared_key::derive_shared_key_sra_side(
            &sra_ephemeral_sk,
            &consent_sk.public_key(),
            &su_nonce,
        )
        .unwrap();
        let nonce_fr = Fr::from_le_bytes_mod_order(&su_nonce);
        let sra_sk_raw: [u8; 32] = sra_side.secret.to_bytes().into();
        // Same reduction `prepare_su_ownership_material` applies on
        // the wallet side: bb 5.x's `schnorr_compute_public_key`
        // aborts the process (uncatchable C++ exception) on any
        // input >= q_Grumpkin. HKDF output is uniform over
        // [0, 2^256) so ~63% of unreduced bytes trip it. Mirror the
        // wallet path here so the comparison stays apples-to-apples.
        let sra_sk_bytes = pso_integrations_shared::witness::reduce_to_grumpkin_sk(&sra_sk_raw);
        let sra_key = derive_grumpkin_public_key(&sra_sk_bytes).unwrap();
        let sra_owner = pso_protocol::ownership::compute_ownership_grumpkin(
            sra_key.pk_x,
            sra_key.pk_y,
            nonce_fr,
        )
        .unwrap();
        let sra_owner_hex = format!("0x{}", hex::encode(fr_to_le32(&sra_owner)));

        assert_eq!(
            witness.derived_owner_le_hex, sra_owner_hex,
            "wallet-side derivedOwner must match the SRA's computed one"
        );
    }

    #[test]
    fn prove_aggregation_rejects_empty_input() {
        let r = prove_su_aggregation(&[], U256::from(1u64), Fr::from(0u64));
        match r {
            Err(L2ClientError::InvalidInput(_)) => {}
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn prepare_td_keypair_is_random() {
        let a = prepare_td_keypair().unwrap();
        let b = prepare_td_keypair().unwrap();
        assert_ne!(a.td_sk_hex, b.td_sk_hex);
        assert_ne!(a.td_derived_owner_le_hex, b.td_derived_owner_le_hex);
    }
}
