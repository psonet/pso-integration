//! Wallet-side flow per the privacy-preserving L2 architecture spec.
//!
//! This module replaces the earlier `aggregate_ownership` design,
//! which was structurally incompatible with §4.1, §4.2, and App. A.
//! See `docs/aggregation-redesign.md` for the rationale and the
//! current state of the cross-repo work.
//!
//! ## Two phases
//!
//! **Phase 1 — Submit TributeDraft on L2.** Wallet builds N per-SU
//! ownership proofs (each with the SU's own `shared_sk` derived via
//! App. A) and folds them via a recursion circuit into one
//! aggregation proof. Calls `TributeDraft.submit(...)` with the
//! recursive proof in the `aggregationProof` slot — same contract
//! signature as today.
//!
//! **Phase 2 — Post-mint TD ownership proof.** Wallet generates a
//! separate ownership proof over the minted TD, using a fresh
//! per-TD keypair. The proof is **not** consumed by L2; it's a
//! wallet-local artifact for later L1-redemption tooling.
//!
//! ## What's implemented today
//!
//! - [`derive_shared_key`] — App. A shared-key reconstruction
//!   (`pso-l2-client::shared_key` module).
//! - [`prepare_su_ownership_material`] — wallet-side counterpart to
//!   the SRA receipt: turns `(consent_sk, pk_cu, su_nonce)` into the
//!   data needed to prove ownership of one SU. The Poseidon5 owner
//!   computation re-uses `pso_protocol::ownership::compute_ownership`.
//! - [`SuOwnershipWitness`] / [`AggregationRequest`] / [`AggregationProofBundle`]
//!   types — the data shape every flow function operates on.
//! - [`prove_su_ownership`], [`aggregate_su_proofs`],
//!   [`prove_td_ownership`] — function signatures match the spec
//!   shape, but the prover call currently returns
//!   `L2ClientError::CircuitNotAvailable`. The Noir circuits these
//!   functions need (per-SU ownership rewritten per §4.2, recursive
//!   aggregation, TD ownership) live in `psonet/pso-zk-circuits` and
//!   are a separate piece of work — see `docs/aggregation-redesign.md`.
//! - [`submit_tribute_draft`] — broadcasts the recursive proof on L2
//!   via the existing `TributeDraft.submit` ABI. Will work once
//!   [`aggregate_su_proofs`] produces real bytes.

use alloy::primitives::{Bytes, FixedBytes, TxHash, U256};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use pso_integrations_shared::witness::{fr_to_le32, ownership_from_public_key};

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
    /// 32-byte LE Fr `derivedOwner` value — matches the SU's on-chain
    /// `derivedOwner` field. The wallet stores this so it doesn't
    /// have to re-derive at proving time, and so a corrupted shared
    /// key surfaces immediately (mismatch with the on-chain value).
    pub derived_owner_le_hex: String,
    /// 33-byte SEC1-compressed `shared_pk` — kept as serialized
    /// bytes so the wallet can persist between sessions. Decompose
    /// back to `(shared_pk_x, shared_pk_y)` via
    /// [`SuOwnershipWitness::shared_pk_coords`].
    pub shared_pk_sec1_hex: String,
    /// 32-byte raw `shared_sk`. **Sensitive.** Persist in keystore
    /// only — never write to plain disk. The shared key is the
    /// signing key the proof's ECDSA verification cares about; if
    /// it leaks the SU becomes claimable by anyone holding the
    /// material.
    pub shared_sk_hex: String,
}

impl SuOwnershipWitness {
    /// SEC1-decompose the stored shared public key into its
    /// big-endian `(x, y)` coordinates — the byte form
    /// `pso_protocol::ownership::compute_ownership` expects.
    pub fn shared_pk_coords(&self) -> Result<([u8; 32], [u8; 32]), L2ClientError> {
        let bytes = hex_to_vec(&self.shared_pk_sec1_hex)?;
        let pk = PublicKey::from_sec1_bytes(&bytes)
            .map_err(|e| L2ClientError::InvalidInput(format!("shared_pk: {e}")))?;
        // sec1_point(false) ⇒ uncompressed `0x04 || x || y` = 65 bytes.
        let sec1 = pk.as_affine().to_sec1_point(false);
        let bytes = sec1.as_bytes();
        if bytes.len() != 65 {
            return Err(L2ClientError::InvalidInput(format!(
                "expected 65-byte uncompressed SEC1 point, got {}",
                bytes.len()
            )));
        }
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        Ok((x, y))
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
    let SharedKey { secret, public } = derive_shared_key(consent_sk, pk_cu, &su_nonce)?;

    // The `su_nonce` is a 32-byte LE-encoded BN254 Fr. Reduce it
    // mod the BN254 scalar field for the Poseidon hash. Same lossy
    // reduction the on-chain side and the original mobile flow use.
    let nonce_fr = Fr::from_le_bytes_mod_order(&su_nonce);
    let owner_fr = ownership_from_public_key(&public, nonce_fr)
        .map_err(|e| L2ClientError::Witness(format!("compute_ownership: {e}")))?;

    Ok(SuOwnershipWitness {
        su_id: format!("0x{:064x}", su_id),
        su_nonce_le_hex: format!("0x{}", hex::encode(su_nonce)),
        derived_owner_le_hex: format!("0x{}", hex::encode(fr_to_le32(&owner_fr))),
        shared_pk_sec1_hex: format!("0x{}", hex::encode(public.to_sec1_bytes())),
        shared_sk_hex: format!("0x{}", hex::encode(secret.to_bytes())),
    })
}

// =====================================================================
// Phase 1, step B — prove SU ownership (one inner proof per SU).
// =====================================================================

/// A single SU-ownership proof. The wallet generates N of these,
/// then folds them via [`aggregate_su_proofs`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuOwnershipProof {
    /// Which SU this proof attests.
    pub su_id: String,
    /// `derivedOwner` value the proof is bound to (32-byte LE hex).
    pub derived_owner_le_hex: String,
    /// `su_hash` value the proof is bound to (32-byte LE hex).
    /// Computed off-chain via
    /// `pso_protocol::nft::compute_spending_unit_hash`. The on-chain
    /// `TributeDraft.submit` reconstructs the same value and matches.
    pub su_hash_le_hex: String,
    /// Raw proof bytes (UltraHonkKeccak combined format).
    pub proof_bytes_hex: String,
}

/// Generate the SU ownership proof for one SU.
///
/// **Not yet implemented at the prover level.** The per-SU ownership
/// Noir circuit needs to be rewritten per §4.2 of the spec (signature
/// over `Poseidon(su_hash || su_nonce)` instead of over the owner
/// directly, with both `owner` and `su_hash` as public inputs). See
/// `docs/aggregation-redesign.md`. This function will start producing
/// real proofs once that circuit lands in `pso-zk-circuits`.
///
/// The signature shape is final — only the implementation body is
/// pending.
pub fn prove_su_ownership(
    _witness: &SuOwnershipWitness,
    _su_hash: Fr,
) -> Result<SuOwnershipProof, L2ClientError> {
    Err(L2ClientError::CircuitNotAvailable {
        detail: "per-SU ownership Noir circuit needs rewrite per §4.2 \
             (signature over Poseidon(su_hash || su_nonce) with su_hash + \
             owner as public inputs). See docs/aggregation-redesign.md."
            .into(),
    })
}

// =====================================================================
// Phase 1, step C — fold N SU proofs into one recursive proof.
// =====================================================================

/// Inputs to [`aggregate_su_proofs`].
#[derive(Debug, Clone)]
pub struct AggregationRequest<'a> {
    /// Per-SU ownership proofs, in the order they'll appear in the
    /// recursive proof's public inputs and the `TributeDraft.submit`
    /// `suIds` calldata. Length ≥ 1.
    pub su_proofs: &'a [SuOwnershipProof],
    /// TD-level commitment the wallet picked for this TributeDraft.
    /// Computed by [`prepare_td_keypair`] before aggregation.
    pub td_derived_owner_le: [u8; 32],
}

/// Fold N SU ownership proofs into one recursive proof via the
/// Noir recursion pattern (each inner proof is verified in-circuit
/// using a compile-time-pinned VK).
///
/// **Not yet implemented.** The recursion aggregation circuit
/// (`pso-recursive-aggregation-circuit-n*`) needs to be added to
/// `pso-zk-circuits` — there's no current Noir circuit that does
/// this folding. See `docs/aggregation-redesign.md`. The function
/// signature is final.
pub fn aggregate_su_proofs(
    request: AggregationRequest<'_>,
) -> Result<AggregationProofBundle, L2ClientError> {
    if request.su_proofs.is_empty() {
        return Err(L2ClientError::InvalidInput(
            "at least one SU ownership proof required".into(),
        ));
    }
    Err(L2ClientError::CircuitNotAvailable {
        detail: format!(
            "recursive aggregation Noir circuit not yet built (would aggregate \
             {} SU proofs into one recursive proof). See \
             docs/aggregation-redesign.md.",
            request.su_proofs.len()
        ),
    })
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
        .send()
        .await
        .map_err(|e| L2ClientError::Contract(format!("TD submit: {e}")))?;
    Ok(*pending.tx_hash())
}

// =====================================================================
// Phase 2 — post-mint TD ownership proof (wallet-local artifact).
// =====================================================================

/// TD-level keypair + nonce material the wallet rolls before
/// submitting a TributeDraft. The wallet persists this; it's
/// needed in Phase 2 to produce the TD ownership proof for L1
/// redemption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdOwnershipMaterial {
    /// 32-byte raw `td_sk`. **Sensitive.**
    pub td_sk_hex: String,
    /// 33-byte SEC1-compressed `td_pk`.
    pub td_pk_sec1_hex: String,
    /// 32-byte LE Fr nonce used during owner derivation.
    pub td_nonce_le_hex: String,
    /// 32-byte LE Fr `derivedOwner` value — what the wallet passes
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
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let td_sk = SecretKey::from_slice(&sk_bytes)
        .map_err(|e| L2ClientError::InvalidInput(format!("td_sk: {e}")))?;
    let td_pk = td_sk.public_key();

    let mut nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_fr = Fr::from_le_bytes_mod_order(&nonce_bytes);

    let owner_fr = ownership_from_public_key(&td_pk, nonce_fr)
        .map_err(|e| L2ClientError::Witness(format!("compute_ownership: {e}")))?;

    Ok(TdOwnershipMaterial {
        td_sk_hex: format!("0x{}", hex::encode(td_sk.to_bytes())),
        td_pk_sec1_hex: format!("0x{}", hex::encode(td_pk.to_sec1_bytes())),
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
// Convenience: assemble the bundle once both proofs are built.
// =====================================================================

/// Bundle the recursive proof + per-SU + TD material into the
/// `AggregationProofBundle` the on-chain `TributeDraft.submit`
/// consumes. Until the prover steps work, this stays unused; kept
/// here so the call graph from CLI → library is complete.
pub fn assemble_aggregation_bundle(
    tribute_draft_id: U256,
    td_material: &TdOwnershipMaterial,
    su_proofs: &[SuOwnershipProof],
    recursive_proof_bytes: &[u8],
    tier_label: &str,
    tier_n: u32,
    circuit_hash_be: [u8; 32],
) -> AggregationProofBundle {
    AggregationProofBundle {
        tribute_draft_id: format!("0x{:064x}", tribute_draft_id),
        td_derived_owner: td_material.td_derived_owner_le_hex.clone(),
        su_ids: su_proofs.iter().map(|p| p.su_id.clone()).collect(),
        tier: AggregationTier {
            tier_n,
            label: tier_label.to_string(),
            circuit_hash: format!("0x{}", hex::encode(circuit_hash_be)),
        },
        proof_bytes_hex: format!("0x{}", hex::encode(recursive_proof_bytes)),
    }
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

        // SRA side: derive shared_pk from its own ephemeral_sk + the
        // wallet's consent_pk, then compute the same owner.
        let sra_side = crate::shared_key::derive_shared_key_sra_side(
            &sra_ephemeral_sk,
            &consent_sk.public_key(),
            &su_nonce,
        )
        .unwrap();
        let nonce_fr = Fr::from_le_bytes_mod_order(&su_nonce);
        let sra_owner = ownership_from_public_key(&sra_side.public, nonce_fr).unwrap();
        let sra_owner_hex = format!("0x{}", hex::encode(fr_to_le32(&sra_owner)));

        assert_eq!(
            witness.derived_owner_le_hex, sra_owner_hex,
            "wallet-side derivedOwner must match the SRA's computed one"
        );
    }

    #[test]
    fn prove_su_ownership_signals_circuit_not_available() {
        let consent_sk = random_secret_key();
        let sra_eph = random_secret_key();
        let witness = prepare_su_ownership_material(
            &consent_sk,
            &sra_eph.public_key(),
            [0xcc; 32],
            U256::from(1u64),
        )
        .unwrap();
        let su_hash = Fr::from(1u64);
        match prove_su_ownership(&witness, su_hash) {
            Err(L2ClientError::CircuitNotAvailable { .. }) => {}
            other => panic!("expected CircuitNotAvailable, got {other:?}"),
        }
    }

    #[test]
    fn aggregate_rejects_empty_input() {
        let req = AggregationRequest {
            su_proofs: &[],
            td_derived_owner_le: [0u8; 32],
        };
        match aggregate_su_proofs(req) {
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
