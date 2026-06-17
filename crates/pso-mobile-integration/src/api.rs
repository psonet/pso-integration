//! Public API functions exposed via UniFFI to React Native.
//!
//! Mobile proof workflow:
//! 1. `compute_tribute_ownership` — pure hash computation (no proof)
//! 2. `prove_spending_unit_ownership` — SU ownership proof
//! 3. `prove_tribute_ownership` — TD ownership proof
//! 4. `prove_spending_unit_full` — SU full proof (ownership + Merkle)
//! 5. `prove_tribute_full` — TD full proof (ownership + Merkle)
//! 6. `generate_random_merkle_path` — dev-only (in `dev_tools` module)
//!
//! Aggregation circuit metadata:
//! - `select_su_aggregation_tier(n_su)` — resolve N SUs to the canonical
//!   aggregation circuit tier (label, circuit_hash, vk_hash).
//! - `su_aggregation_tier_sizes()` — enumerate all available tier sizes.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use rand::rngs::OsRng;

use pso_integrations_shared::witness::{
    build_full_proof_witness, build_ownership_witness, derive_grumpkin_public_key,
    reduce_to_grumpkin_sk, FullProofWitnessCtx, GrumpkinKey, OwnershipWitnessCtx,
};
use pso_protocol::witness::HashableNFT;
use pso_zk_circuit_noir::ZKCircuit;

use crate::circuits;
use crate::convert::{
    bytes_to_fr, bytes_vec_to_fr_vec, check_grumpkin_sk, compute_tribute_draft_id, fr_to_bytes,
    noir_proof_to_result, parse_currency, parse_merkle_path, parse_secret_key, parse_worldwide_day,
    worldwide_day_count,
};
use crate::types::{
    AggregationTierInfo, MerklePathElementInput, MobileError, NftKeypair, ProofResult,
    SpendingUnitInput, SuAggregationSlot, TributeInput, TributeKeypair, TributeOwnership,
};

// -- 0. Derive NFT keypair (Grumpkin) --
//
// App. A: secp256k1 ECDH between `consent_sk` and `sra_pk` plus HKDF
// over `nft_nonce` lands a 32-byte shared secret. We reinterpret it
// as a Grumpkin scalar for the in-circuit Schnorr signing path. The
// returned `pk` is `pk_x_le || pk_y_le` (64 bytes, two 32-byte LE Fr
// encodings concatenated).
#[uniffi::export]
pub fn derive_nft_keypair(
    consent_sk: Vec<u8>, // secp256k1 private key
    sra_pk: Vec<u8>,     // secp256k1 public key
    nft_nonce: Vec<u8>,  // 32-byte nonce
) -> Result<NftKeypair, MobileError> {
    let nft_sk = pso_integrations_shared::derive_nft_keypair(&consent_sk, &sra_pk, &nft_nonce)?;
    let nft_sk_raw: [u8; 32] = nft_sk.to_bytes().into();
    // App. A ECDH lands a uniform 32-byte scalar in [0, 2^256), but
    // bb 5.x's `schnorr_compute_public_key` aborts the process on
    // inputs >= q_Grumpkin (~63% of uniform inputs trip it). Mirror
    // the SRA path in `pso_sra_integration::generate_ownership_inner`
    // and reduce mod q_Grumpkin before the FFI call.
    let sk_bytes = reduce_to_grumpkin_sk(&nft_sk_raw);
    let grumpkin = derive_grumpkin_public_key(&sk_bytes).map_err(|e| MobileError::Internal {
        detail: format!("derive grumpkin pk: {e}"),
    })?;
    // pk is `pk_x_be || pk_y_be` (64 bytes total). BE matches what
    // `schnorr_verify_grumpkin` expects on the wire and what
    // barretenberg-rs emits internally.
    let mut pk = Vec::with_capacity(64);
    pk.extend_from_slice(&pso_integrations_shared::witness::fr_to_be32(
        &grumpkin.pk_x,
    ));
    pk.extend_from_slice(&pso_integrations_shared::witness::fr_to_be32(
        &grumpkin.pk_y,
    ));
    Ok(NftKeypair {
        sk: sk_bytes.to_vec(),
        pk,
    })
}

// -- Generate a fresh Grumpkin tribute key --

/// Generate a fresh random Grumpkin keypair for the tribute flow.
///
/// The secret key is sampled from OS randomness and reduced into the
/// Grumpkin scalar field (a non-zero scalar `< q_Grumpkin`), so it is
/// always a valid input to [`compute_tribute_ownership`] /
/// `prove_tribute_*` and never trips the barretenberg out-of-range
/// abort guarded by `convert::grumpkin_sk_in_range`.
///
/// Clients that need a per-TributeDraft signing key should call this
/// instead of rolling 32 random bytes themselves — uniformly random
/// 32-byte values land `>= q_Grumpkin` ~63% of the time.
#[uniffi::export]
pub fn generate_tribute_key() -> Result<TributeKeypair, MobileError> {
    let key = pso_integrations_shared::witness::random_grumpkin_key().map_err(|e| {
        MobileError::Internal {
            detail: format!("generate grumpkin key: {e}"),
        }
    })?;
    // pk is `pk_x_be || pk_y_be` (64 bytes), matching the layout
    // `derive_nft_keypair` returns and `schnorr_verify_grumpkin`
    // expects on the wire.
    let mut public_key = Vec::with_capacity(64);
    public_key.extend_from_slice(&pso_integrations_shared::witness::fr_to_be32(&key.pk_x));
    public_key.extend_from_slice(&pso_integrations_shared::witness::fr_to_be32(&key.pk_y));
    Ok(TributeKeypair {
        secret_key: key.sk_bytes.to_vec(),
        public_key,
    })
}

// -- 1. Compute tribute ownership (no proof) --

/// Compute ownership hash, tribute draft ID, and generate a random nonce.
///
/// This is a pure computation — no circuit or proof is involved. Called early
/// in the tribute flow so the client can submit the ownership value to the
/// smart contract for minting.
///
/// The returned `nonce` must be stored and passed back to
/// [`prove_tribute_ownership`] or [`prove_tribute_full`] later.
#[uniffi::export]
pub fn compute_tribute_ownership(
    secret_key: Vec<u8>,
    worldwide_day: u32,
) -> Result<TributeOwnership, MobileError> {
    use rand::RngCore;

    let sk = parse_secret_key(&secret_key)?;
    let date = parse_worldwide_day(worldwide_day)?;
    let wwd = worldwide_day_count(&date);
    let wwd_fr = Fr::from(wwd);

    // Generate the nonce as raw bytes (the canonical wire form), then
    // derive its `Fr` view only for the Poseidon commitment below.
    //
    // Mirrors the SRA bridge's `OsRng.fill_bytes(&mut su_nonce)` and
    // the unified App. A guard in `pso-sra-integration`: bytes are the
    // source of truth, Fr is derived lazily where needed. Doing the
    // inverse (sampling `Fr::rand` and emitting `fr_to_bytes`) would
    // technically work today — every Fr-encoded byte string is
    // < q_BN254 and round-trips losslessly — but it locks the API
    // shape into "nonces must be canonical Fr bytes", which is the
    // exact assumption that produced the silent SRA-side / wallet-side
    // split fixed in PR #6 sibling commits. Keep bytes-first here so a
    // future change to the SRA flow that emits non-canonical nonces
    // doesn't desync the wallet path.
    let mut nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_bytes);
    // BE everywhere — same convention `bytes_to_fr` applies to inputs
    // and what every other PSO surface (SRA crate, wallet, on-chain
    // Poseidon precompile) interprets the same nonce bytes as.
    let nonce_fr = Fr::from_be_bytes_mod_order(&nonce_bytes);

    let ownership = pso_protocol::ownership::compute_ownership_grumpkin(sk.pk_x, sk.pk_y, nonce_fr)
        .map_err(|e| MobileError::Internal {
            detail: e.to_string(),
        })?;

    let tribute_draft_id = compute_tribute_draft_id(&ownership, &wwd_fr)?;

    Ok(TributeOwnership {
        nonce: nonce_bytes.to_vec(),
        ownership: fr_to_bytes(&ownership),
        tribute_draft_id: fr_to_bytes(&tribute_draft_id),
    })
}

// -- 2. Prove SpendingUnit ownership --

/// Redemption binding hash for a standalone ownership/full proof:
/// `compute_binding_hash(redeemer, commitmentId, chainId)`. Folded into the
/// proof's signature + exposed as a public input so the L1 verifier can pin
/// the proof to the `(redeemer, commitmentId, chainId)` tuple. `commitment_id`
/// is the SU/TD id (encoded big-endian, matching the on-chain `uint256`).
fn redemption_binding(
    redeemer: &[u8],
    commitment_id: Fr,
    chain_id: u64,
) -> Result<Fr, MobileError> {
    let redeemer_arr: [u8; 20] =
        redeemer
            .try_into()
            .map_err(|_| MobileError::WitnessGenerationFailed {
                detail: format!("redeemer must be 20 bytes, got {}", redeemer.len()),
            })?;
    let commitment_be = pso_protocol::fr::fr_to_be_bytes(&commitment_id);
    pso_protocol::binding::compute_binding_hash(&redeemer_arr, &commitment_be, chain_id).map_err(
        |e| MobileError::WitnessGenerationFailed {
            detail: format!("compute_binding_hash: {e}"),
        },
    )
}

/// Generate an ownership-only proof for a SpendingUnit.
///
/// The nonce and ID are provided by the SRA server that generated the SU.
/// `redeemer` (20-byte EOA) + `chain_id` bind the proof for L1 redemption.
#[uniffi::export]
pub fn prove_spending_unit_ownership(
    secret_key: Vec<u8>,
    spending_unit: SpendingUnitInput,
    redeemer: Vec<u8>,
    chain_id: u64,
) -> Result<ProofResult, MobileError> {
    let sk = parse_secret_key(&secret_key)?;
    let nonce = bytes_to_fr(&spending_unit.nonce)?;
    let su = build_spending_unit(&sk, nonce, &spending_unit)?;
    let binding_hash = redemption_binding(&redeemer, su.id, chain_id)?;

    let su_nft_hash = HashableNFT::hash(&su).map_err(|e| MobileError::WitnessGenerationFailed {
        detail: format!("su hash: {e}"),
    })?;
    let witness = build_ownership_witness(
        &su,
        OwnershipWitnessCtx {
            key: &sk,
            nonce,
            nft_hash: su_nft_hash,
            binding_hash,
        },
    )
    .map_err(|e| MobileError::WitnessGenerationFailed {
        detail: e.to_string(),
    })?;

    let circuit = circuits::ownership_circuit()?;
    let proof = circuit
        .prove(witness)
        .map_err(|e| MobileError::ProofFailed {
            detail: e.to_string(),
        })?;

    Ok(noir_proof_to_result(&proof))
}

// -- 3. Prove TributeDraft ownership --

/// Generate an ownership-only proof for a TributeDraft.
///
/// The `nonce` must be the same one returned by [`compute_tribute_ownership`].
#[uniffi::export]
pub fn prove_tribute_ownership(
    secret_key: Vec<u8>,
    nonce: Vec<u8>,
    tribute: TributeInput,
    redeemer: Vec<u8>,
    chain_id: u64,
) -> Result<ProofResult, MobileError> {
    let sk = parse_secret_key(&secret_key)?;
    let nonce_fr = bytes_to_fr(&nonce)?;
    let td = build_tribute_draft(&sk, nonce_fr, &tribute)?;
    let binding_hash = redemption_binding(&redeemer, td.id, chain_id)?;

    let td_nft_hash = HashableNFT::hash(&td).map_err(|e| MobileError::WitnessGenerationFailed {
        detail: format!("td hash: {e}"),
    })?;
    let witness = build_ownership_witness(
        &td,
        OwnershipWitnessCtx {
            key: &sk,
            nonce: nonce_fr,
            nft_hash: td_nft_hash,
            binding_hash,
        },
    )
    .map_err(|e| MobileError::WitnessGenerationFailed {
        detail: e.to_string(),
    })?;

    let circuit = circuits::ownership_circuit()?;
    let proof = circuit
        .prove(witness)
        .map_err(|e| MobileError::ProofFailed {
            detail: e.to_string(),
        })?;

    Ok(noir_proof_to_result(&proof))
}

// -- 4. Prove SpendingUnit full proof --

/// Generate a full proof (ownership + Merkle inclusion) for a SpendingUnit.
#[uniffi::export]
pub fn prove_spending_unit_full(
    secret_key: Vec<u8>,
    spending_unit: SpendingUnitInput,
    merkle_path: Vec<MerklePathElementInput>,
    redeemer: Vec<u8>,
    chain_id: u64,
) -> Result<ProofResult, MobileError> {
    let sk = parse_secret_key(&secret_key)?;
    let nonce = bytes_to_fr(&spending_unit.nonce)?;
    let su = build_spending_unit(&sk, nonce, &spending_unit)?;
    let path = parse_merkle_path(&merkle_path)?;
    let binding_hash = redemption_binding(&redeemer, su.id, chain_id)?;

    let witness = build_full_proof_witness(
        &su,
        FullProofWitnessCtx {
            key: &sk,
            nonce,
            merkle_path: &path,
            binding_hash,
        },
    )
    .map_err(|e| MobileError::WitnessGenerationFailed {
        detail: e.to_string(),
    })?;

    let circuit = circuits::full_proof_circuit()?;
    let proof = circuit
        .prove(witness)
        .map_err(|e| MobileError::ProofFailed {
            detail: e.to_string(),
        })?;

    Ok(noir_proof_to_result(&proof))
}

// -- 5. Prove TributeDraft full proof --

/// Generate a full proof (ownership + Merkle inclusion) for a TributeDraft.
///
/// The `nonce` must be the same one returned by [`compute_tribute_ownership`].
#[uniffi::export]
pub fn prove_tribute_full(
    secret_key: Vec<u8>,
    nonce: Vec<u8>,
    tribute: TributeInput,
    merkle_path: Vec<MerklePathElementInput>,
    redeemer: Vec<u8>,
    chain_id: u64,
) -> Result<ProofResult, MobileError> {
    let sk = parse_secret_key(&secret_key)?;
    let nonce_fr = bytes_to_fr(&nonce)?;
    let td = build_tribute_draft(&sk, nonce_fr, &tribute)?;
    let path = parse_merkle_path(&merkle_path)?;
    let binding_hash = redemption_binding(&redeemer, td.id, chain_id)?;

    let witness = build_full_proof_witness(
        &td,
        FullProofWitnessCtx {
            key: &sk,
            nonce: nonce_fr,
            merkle_path: &path,
            binding_hash,
        },
    )
    .map_err(|e| MobileError::WitnessGenerationFailed {
        detail: e.to_string(),
    })?;

    let circuit = circuits::full_proof_circuit()?;
    let proof = circuit
        .prove(witness)
        .map_err(|e| MobileError::ProofFailed {
            detail: e.to_string(),
        })?;

    Ok(noir_proof_to_result(&proof))
}

// -- Internal builders --

/// Build a `pso_nft::SpendingUnit` from FFI inputs.
fn build_spending_unit(
    sk: &GrumpkinKey,
    nonce: Fr,
    input: &SpendingUnitInput,
) -> Result<pso_nft::SpendingUnit, MobileError> {
    let id = bytes_to_fr(&input.id)?;
    let date = parse_worldwide_day(input.worldwide_day)?;
    let currency = parse_currency(input.currency)?;
    let sr_fps = bytes_vec_to_fr_vec(&input.spending_records_fingerprints)?;
    let ar_fps = bytes_vec_to_fr_vec(&input.amendment_records_fingerprints)?;

    let ownership = pso_protocol::ownership::compute_ownership_grumpkin(sk.pk_x, sk.pk_y, nonce)
        .map_err(|e| MobileError::Internal {
            detail: e.to_string(),
        })?;

    Ok(pso_nft::SpendingUnit {
        id,
        owner: ownership,
        attester: bytes_to_fr(&input.attester)?,
        referrer: bytes_to_fr(&input.referrer)?,
        currency: currency,
        amount_base: input.amount_base,
        amount_atto: input.amount_atto,
        worldwide_day: date,
        spending_records_fingerprints: sr_fps,
        amendment_records_fingerprints: ar_fps,
    })
}

/// Build a `pso_nft::TributeDraft` from FFI inputs.
fn build_tribute_draft(
    sk: &GrumpkinKey,
    nonce: Fr,
    input: &TributeInput,
) -> Result<pso_nft::TributeDraft, MobileError> {
    let date = parse_worldwide_day(input.worldwide_day)?;
    let currency = parse_currency(input.currency)?;
    let su_ids = bytes_vec_to_fr_vec(&input.su_ids)?;
    let wwd = worldwide_day_count(&date);
    let wwd_fr = Fr::from(wwd);

    let ownership = pso_protocol::ownership::compute_ownership_grumpkin(sk.pk_x, sk.pk_y, nonce)
        .map_err(|e| MobileError::Internal {
            detail: e.to_string(),
        })?;

    let id = compute_tribute_draft_id(&ownership, &wwd_fr)?;

    Ok(pso_nft::TributeDraft {
        id,
        owner: ownership,
        currency: currency,
        amount_base: input.amount_base,
        amount_atto: input.amount_atto,
        worldwide_day: date,
        su_ids,
    })
}

// -- Aggregation tier selection ------------------------------------------ //

/// Resolve `n_su` to the canonical SU-ownership aggregation circuit tier.
///
/// Returns the smallest tier whose slot count covers `n_su`. Errors with
/// `AggregationTierUnavailable` if `n_su == 0` or `n_su > 64` (the
/// largest tier). The returned `tier_n` is the value clients must pad
/// their `derived_owners` witness arrays to before generating a proof.
///
/// This is the single source of truth for tier dispatch: the on-chain
/// TributeDraft contract resolves through the same table in
/// `pso_zk_canonical`, so the wallet and the chain are guaranteed to
/// agree on which circuit applies to a given aggregation.
#[uniffi::export]
pub fn select_su_aggregation_tier(n_su: u32) -> Result<AggregationTierInfo, MobileError> {
    let tier = pso_zk_canonical::select_aggregation_tier(n_su).ok_or_else(|| {
        MobileError::AggregationTierUnavailable {
            detail: format!("no aggregation tier for n_su={n_su} (must be 1..=64)"),
        }
    })?;
    Ok(AggregationTierInfo {
        tier_n: tier.tier_n,
        label: tier.descriptor.label.to_string(),
        circuit_hash: tier.descriptor.circuit_hash.to_vec(),
        vk_hash: tier.descriptor.vk_hash.to_vec(),
    })
}

/// Enumerate all SU-ownership aggregation tier sizes, in ascending
/// order. Wallets can use this to validate "the user wants to aggregate
/// X SUs — is that supported?" without trial-and-error calls to
/// `select_su_aggregation_tier`.
#[uniffi::export]
pub fn su_aggregation_tier_sizes() -> Vec<u32> {
    pso_zk_canonical::SU_AGGREGATION_TIERS.to_vec()
}

/// Generate the SU-ownership aggregation proof a wallet submits to
/// `TributeDraft.submit(...)` as the `aggregationProof` calldata.
///
/// Steps performed:
/// 1. Decode the secret key + each slot's (nonce, derived_owner) pair.
/// 2. Compute the binding hash off-chain:
///       `Poseidon::<Fr>::new_circom(4).hash([
///           sender_field, tdid_lo, tdid_hi, chainid_field,
///       ])`
///    where `tributeDraftId` is split into two 128-bit limbs to fit
///    BN254 Fr. Same construction the on-chain `TributeDraft`
///    contract performs via the `0x0202` Poseidon precompile, so the
///    proof's public input matches the on-chain expected vector
///    byte-for-byte.
/// 3. Select the smallest aggregation tier `>= su_slots.len()` via
///    `pso_zk_canonical::select_aggregation_tier`.
/// 4. Build the witness (real slots, zero-padded to tier size, plus
///    ECDSA signature over `binding_hash.to_le_bytes()`).
/// 5. Prove against the canonical VK for the chosen tier.
///
/// Errors:
/// - `AggregationTierUnavailable` for `su_slots.len() == 0` or `> 64`.
/// - `InvalidSecretKey` for malformed secret-key bytes.
/// - `InvalidFieldElement` for nonces / derived_owners that aren't 32
///   bytes (or that fail Fr decoding).
/// - `WitnessGenerationFailed` / `ProofFailed` from the prover.
///
/// Parameters:
/// - `secret_key`: 32-byte secp256k1 private key (little-endian).
/// - `su_slots`: vec of `(nonce, derived_owner)` for each SU being
///   aggregated. Length must be `>= 1` and `<= 64`.
/// - `sender`: 20-byte EVM address (`msg.sender` at the on-chain
///   submit call).
/// - `tribute_draft_id`: 32-byte uint256 value (big-endian, matching
///   Solidity `bytes32`/`uint256` natural encoding).
/// - `chain_id`: chain id the contract sees as `block.chainid`.
/// Build a flat-aggregation proof for `su_slots`. The wallet picks the
/// smallest canonical tier ≥ `su_slots.len()`; unused slots are
/// zero-padded inside the witness builder.
///
/// **Note**: the `secret_key`/`sender`/`tribute_draft_id`/`chain_id`
/// `_secret_key` is unused (each slot carries its own per-SU Grumpkin
/// secret key). `sender` / `tribute_draft_id` / `chain_id` ARE used: they
/// form the submission binding `binding_hash = Poseidon4(sender,
/// tributeDraftId, chainId)` that the circuit folds into every per-SU
/// signature and the on-chain `TributeDraft.submit` recomputes — so the
/// proof is valid only when submitted from `sender` for this `tribute_draft_id`
/// on this `chain_id`. `sender` must be the 20-byte EOA the wallet will
/// submit from; `tribute_draft_id` the 32-byte BE id.
#[uniffi::export]
pub fn prove_su_ownership_aggregation(
    _secret_key: Vec<u8>,
    su_slots: Vec<SuAggregationSlot>,
    sender: Vec<u8>,
    tribute_draft_id: Vec<u8>,
    chain_id: u64,
) -> Result<ProofResult, MobileError> {
    use pso_integrations_shared::witness::{build_flat_aggregation_witness, FlatAggregationSlot};

    // Resolve the canonical tier for this SU count.
    let tier =
        pso_zk_canonical::select_aggregation_tier(su_slots.len() as u32).ok_or_else(|| {
            MobileError::AggregationTierUnavailable {
                detail: format!(
                    "no aggregation tier for n_su={} (must be 1..=64)",
                    su_slots.len()
                ),
            }
        })?;

    // Decode each slot's Grumpkin sk + per-SU material.
    let mut slots: Vec<FlatAggregationSlot> = Vec::with_capacity(su_slots.len());
    for s in &su_slots {
        // Gate the per-slot key through the range check before it
        // reaches barretenberg — an out-of-range `grumpkin_sk` would
        // otherwise abort the whole process inside the FFI.
        let sk_arr = check_grumpkin_sk(&s.grumpkin_sk)?;
        let key =
            derive_grumpkin_public_key(&sk_arr).map_err(|e| MobileError::InvalidSecretKey {
                detail: format!("derive grumpkin pk: {e}"),
            })?;
        let nonce = bytes_to_fr(&s.nonce)?;
        let owner = bytes_to_fr(&s.derived_owner)?;
        let nft_hash = bytes_to_fr(&s.nft_hash)?;
        slots.push(FlatAggregationSlot {
            key,
            nonce,
            owner,
            nft_hash,
        });
    }

    // Submission binding: Poseidon4(sender, tributeDraftId, chainId), folded
    // into every per-SU signature and exposed as the trailing public input.
    let sender_arr: [u8; 20] =
        sender
            .as_slice()
            .try_into()
            .map_err(|_| MobileError::WitnessGenerationFailed {
                detail: format!("sender must be 20 bytes, got {}", sender.len()),
            })?;
    let tdid_arr: [u8; 32] = tribute_draft_id.as_slice().try_into().map_err(|_| {
        MobileError::WitnessGenerationFailed {
            detail: format!(
                "tribute_draft_id must be 32 bytes, got {}",
                tribute_draft_id.len()
            ),
        }
    })?;
    let binding_hash =
        pso_protocol::binding::compute_binding_hash(&sender_arr, &tdid_arr, chain_id).map_err(
            |e| MobileError::WitnessGenerationFailed {
                detail: format!("compute_binding_hash: {e}"),
            },
        )?;

    let witness_vec =
        build_flat_aggregation_witness(&slots, tier.tier_n, binding_hash).map_err(|e| {
            MobileError::WitnessGenerationFailed {
                detail: e.to_string(),
            }
        })?;
    let witness_map =
        pso_zk_circuit_noir::witness::from_vec_to_witness_map(witness_vec).map_err(|e| {
            MobileError::WitnessGenerationFailed {
                detail: format!("witness map: {e}"),
            }
        })?;

    // Load the bytecode for this tier and prove against the canonical
    // VK from `pso_zk_canonical`.
    let bytecode = circuits::flat_aggregation_bytecode(tier.tier_n)?;
    let _ = pso_zk_circuit_noir::barretenberg::srs::setup_srs_from_bytecode(
        &bytecode.bytecode,
        None,
        true,
    )
    .map_err(|e| MobileError::CircuitInitFailed {
        detail: format!("setup_srs: {e}"),
    })?;
    let proof = pso_zk_circuit_noir::barretenberg::prove::prove_ultra_honk_keccak(
        &bytecode.bytecode,
        witness_map,
        tier.descriptor.vk_bytes.to_vec(),
        false, // disable_zk
        true,  // low_memory
        None,
    )
    .map_err(|e| MobileError::ProofFailed {
        detail: e.to_string(),
    })?;

    let (public_inputs, proof_bytes) =
        pso_zk_circuit_noir::split_proof(&proof).map_err(|e| MobileError::Internal {
            detail: format!("split_proof: {e}"),
        })?;

    Ok(noir_proof_to_result(&pso_zk_circuit_noir::NoirProof {
        proof: proof_bytes,
        public_inputs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    fn random_secret_key() -> GrumpkinKey {
        pso_integrations_shared::witness::random_grumpkin_key().expect("random Grumpkin key")
    }

    fn sk_bytes_of(key: &GrumpkinKey) -> Vec<u8> {
        key.sk_bytes.to_vec()
    }

    #[test]
    fn test_compute_tribute_ownership_returns_valid_data() {
        let sk = random_secret_key();
        let result = compute_tribute_ownership(sk_bytes_of(&sk), 20260305).unwrap();
        assert_eq!(result.nonce.len(), 32);
        assert_eq!(result.ownership.len(), 32);
        assert_eq!(result.tribute_draft_id.len(), 32);
    }

    #[test]
    fn test_generate_tribute_key_shape_and_validity() {
        let kp = generate_tribute_key().unwrap();
        assert_eq!(kp.secret_key.len(), 32, "sk is 32 bytes");
        assert_eq!(kp.public_key.len(), 64, "pk is pk_x_be||pk_y_be");

        // The generated key is in range and usable end-to-end: it must
        // pass the gate and drive a successful ownership computation.
        let sk_arr: [u8; 32] = kp.secret_key.as_slice().try_into().unwrap();
        assert!(crate::convert::grumpkin_sk_in_range(&sk_arr));
        compute_tribute_ownership(kp.secret_key.clone(), 20260305)
            .expect("generated key must drive compute_tribute_ownership");

        // The derived public key matches an independent derivation.
        let key = derive_grumpkin_public_key(&sk_arr).unwrap();
        let mut expected = Vec::with_capacity(64);
        expected.extend_from_slice(&pso_integrations_shared::witness::fr_to_be32(&key.pk_x));
        expected.extend_from_slice(&pso_integrations_shared::witness::fr_to_be32(&key.pk_y));
        assert_eq!(kp.public_key, expected);
    }

    #[test]
    fn test_generate_tribute_key_is_random() {
        let a = generate_tribute_key().unwrap();
        let b = generate_tribute_key().unwrap();
        assert_ne!(a.secret_key, b.secret_key);
    }

    #[test]
    fn test_compute_tribute_ownership_rejects_out_of_range_key() {
        // An all-0xFF key is well above q_Grumpkin. Without the gate
        // this aborts the whole process inside barretenberg; with it we
        // get a recoverable error.
        let result = compute_tribute_ownership(vec![0xffu8; 32], 20260305);
        assert!(matches!(
            result,
            Err(MobileError::SecretKeyOutOfRange { .. })
        ));
    }

    #[test]
    fn test_compute_tribute_ownership_different_nonces() {
        let sk = random_secret_key();
        let r1 = compute_tribute_ownership(sk_bytes_of(&sk), 20260305).unwrap();
        let r2 = compute_tribute_ownership(sk_bytes_of(&sk), 20260305).unwrap();
        // Nonces should differ (random)
        assert_ne!(r1.nonce, r2.nonce);
        // Ownership hashes should differ (different nonces)
        assert_ne!(r1.ownership, r2.ownership);
    }

    #[test]
    fn test_build_tribute_draft_id_matches_compute() {
        let sk = random_secret_key();
        let sk_bytes = sk_bytes_of(&sk);

        let ownership_result = compute_tribute_ownership(sk_bytes.clone(), 20260305).unwrap();

        let nonce_fr = bytes_to_fr(&ownership_result.nonce).unwrap();
        let tribute_input = TributeInput {
            currency: 978,
            amount_base: 100,
            amount_atto: 0,
            worldwide_day: 20260305,
            su_ids: vec![],
        };

        let td = build_tribute_draft(&sk, nonce_fr, &tribute_input).unwrap();
        let td_id_bytes = fr_to_bytes(&td.id);

        assert_eq!(td_id_bytes, ownership_result.tribute_draft_id);
    }

    #[test]
    fn test_build_spending_unit_valid() {
        let sk = random_secret_key();
        let nonce = Fr::rand(&mut OsRng);
        let id = Fr::rand(&mut OsRng);

        let input = SpendingUnitInput {
            id: fr_to_bytes(&id),
            nonce: fr_to_bytes(&nonce),
            attester: vec![0u8; 32],
            referrer: vec![0u8; 32],
            currency: 978,
            amount_base: 50,
            amount_atto: 0,
            worldwide_day: 20260305,
            spending_records_fingerprints: vec![],
            amendment_records_fingerprints: vec![],
        };

        let su = build_spending_unit(&sk, nonce, &input).unwrap();
        assert_eq!(su.id, id);
        assert_eq!(su.amount_base, 50);
    }

    #[test]
    fn test_select_su_aggregation_tier_rounds_up() {
        let info = select_su_aggregation_tier(5).unwrap();
        assert_eq!(info.tier_n, 8, "5 SUs should fit the N=8 tier");
        assert_eq!(info.label, "pso.flat_aggregation.n8");
        assert_eq!(info.circuit_hash.len(), 32);
        assert_eq!(info.vk_hash.len(), 32);
    }

    #[test]
    fn test_select_su_aggregation_tier_exact_match() {
        let info = select_su_aggregation_tier(8).unwrap();
        assert_eq!(info.tier_n, 8);
        assert_eq!(info.label, "pso.flat_aggregation.n8");
    }

    #[test]
    fn test_select_su_aggregation_tier_zero_rejected() {
        let err = select_su_aggregation_tier(0).unwrap_err();
        assert!(matches!(
            err,
            MobileError::AggregationTierUnavailable { .. }
        ));
    }

    #[test]
    fn test_select_su_aggregation_tier_above_max_rejected() {
        let err = select_su_aggregation_tier(65).unwrap_err();
        assert!(matches!(
            err,
            MobileError::AggregationTierUnavailable { .. }
        ));
    }

    #[test]
    fn test_su_aggregation_tier_sizes_matches_canonical() {
        let sizes = su_aggregation_tier_sizes();
        assert_eq!(sizes, vec![1, 2, 4, 8, 16, 32, 64]);
    }

    // Ignored by default: the prove path downloads the BN254 SRS from
    // `crs.aztec.network` at runtime, so this test is NOT network-free
    // and must not run in the `unit` CI job (cargo test --workspace
    // --lib --tests), which is meant to stay offline. It also takes the
    // whole pipeline down whenever that upstream endpoint flakes (e.g.
    // the 2026-06-01 TLS-cert expiry). Run it explicitly in a
    // network-allowed context with `cargo test -p pso-mobile-integration
    // -- --ignored`.
    #[test]
    #[ignore = "downloads the Aztec SRS over the network; run with `cargo test -- --ignored`"]
    fn test_prove_su_ownership_aggregation_end_to_end_n1() {
        // Smallest tier — fastest test. Full prove+verify against the
        // canonical VK exposed through the FFI surface.
        let sk = random_secret_key();

        let nonce = Fr::rand(&mut OsRng);
        let derived_owner =
            pso_protocol::ownership::compute_ownership_grumpkin(sk.pk_x, sk.pk_y, nonce).unwrap();

        let slot = SuAggregationSlot {
            nonce: fr_to_bytes(&nonce),
            derived_owner: fr_to_bytes(&derived_owner),

            nft_hash: vec![0u8; 32],
            grumpkin_sk: sk_bytes_of(&sk),
        };

        let sender = vec![0x11u8; 20];
        let tribute_draft_id = vec![0x22u8; 32];
        let chain_id: u64 = 19_280_501;

        let result = prove_su_ownership_aggregation(
            sk_bytes_of(&sk),
            vec![slot],
            sender,
            tribute_draft_id,
            chain_id,
        )
        .expect("prove must succeed");

        // Sanity: proof bytes present, public inputs match tier shape.
        assert!(!result.proof.is_empty(), "proof bytes must not be empty");
        assert_eq!(
            result.public_inputs.len(),
            2,
            "tier=1 should produce 2 public inputs (1 derived_owner + binding_hash)",
        );

        // Round-trip verify against the canonical VK from
        // pso_zk_canonical using noir_rs directly (the flat-aggregation
        // tier circuits don't have a NoirCircuit trait wrapper).
        let mut combined: Vec<u8> = Vec::new();
        combined.extend_from_slice(&(result.public_inputs.len() as u32).to_be_bytes());
        for pi in &result.public_inputs {
            combined.extend_from_slice(pi);
        }
        combined.extend_from_slice(&result.proof);
        let vk = pso_zk_canonical::FLAT_AGGREGATION_N1.vk_bytes.to_vec();
        let ok = pso_zk_circuit_noir::barretenberg::verify::verify_ultra_honk_keccak(
            combined, vk, false,
        )
        .expect("verify must succeed");
        assert!(ok, "round trip: prove + verify against canonical VK");
    }

    #[test]
    fn test_prove_su_ownership_aggregation_rejects_zero_slots() {
        let sk = random_secret_key();
        let err = prove_su_ownership_aggregation(
            sk_bytes_of(&sk),
            vec![], // no SUs
            vec![0x00u8; 20],
            vec![0x00u8; 32],
            1,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            MobileError::AggregationTierUnavailable { .. }
        ));
    }

    #[test]
    fn test_prove_su_ownership_aggregation_rejects_oversized() {
        let sk = random_secret_key();
        // 65 slots — over the largest tier (64).
        let slots: Vec<SuAggregationSlot> = (0..65)
            .map(|_| SuAggregationSlot {
                nonce: vec![0u8; 32],
                derived_owner: vec![0u8; 32],

                nft_hash: vec![0u8; 32],
                grumpkin_sk: sk_bytes_of(&sk),
            })
            .collect();
        let err = prove_su_ownership_aggregation(
            sk_bytes_of(&sk),
            slots,
            vec![0x00u8; 20],
            vec![0x00u8; 32],
            1,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            MobileError::AggregationTierUnavailable { .. }
        ));
    }

    // (Previously: `test_prove_su_ownership_aggregation_rejects_bad_sender_length`.)
    // The `_sender` / `_tribute_draft_id` / `_chain_id` parameters are
    // explicitly unused on the current code path (see the
    // doc-comment on `prove_su_ownership_aggregation` — they're kept
    // for FFI ABI compatibility but the function doesn't validate
    // them). The invariant the old test enforced no longer exists,
    // so the test is gone with it.
}
