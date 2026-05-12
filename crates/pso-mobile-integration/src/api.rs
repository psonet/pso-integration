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
use ark_ff::UniformRand;
use rand::rngs::OsRng;

use pso_integrations_shared::witness::{
    build_full_proof_witness, build_ownership_witness, FullProofWitnessCtx, OwnershipWitnessCtx,
};
use pso_zk_circuit_noir::ZKCircuit;

use crate::circuits;
use crate::convert::{
    bytes_to_fr, bytes_vec_to_fr_vec, compute_tribute_draft_id, fr_to_bytes, noir_proof_to_result,
    parse_currency, parse_merkle_path, parse_secret_key, parse_worldwide_day, worldwide_day_count,
};
use crate::types::{
    AggregationTierInfo, MerklePathElementInput, MobileError, NftKeypair, ProofResult,
    SpendingUnitInput, SuAggregationSlot, TributeInput, TributeOwnership,
};

// -- 0. Derive NFT keypair --
#[uniffi::export]
pub fn derive_nft_keypair(
    consent_sk: Vec<u8>, // Secp256k1 private key
    sra_pk: Vec<u8>,     // Secp256k1 public key
    nft_nonce: Vec<u8>,  // 32-byte nonce (should be valid Fr)
) -> Result<NftKeypair, MobileError> {
    let nft_sk = pso_integrations_shared::derive_nft_keypair(&consent_sk, &sra_pk, &nft_nonce)?;
    let nft_pk = nft_sk.public_key();

    Ok(NftKeypair {
        sk: nft_sk.to_bytes().to_vec(),
        pk: nft_pk.to_sec1_bytes().to_vec(),
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
    let sk = parse_secret_key(&secret_key)?;
    let date = parse_worldwide_day(worldwide_day)?;
    let wwd = worldwide_day_count(&date);
    let wwd_fr = Fr::from(wwd);

    let nonce = Fr::rand(&mut OsRng);

    let ownership =
        pso_integrations_shared::witness::ownership_from_public_key(&sk.public_key(), nonce)
            .map_err(|e| MobileError::Internal {
                detail: e.to_string(),
            })?;

    let tribute_draft_id = compute_tribute_draft_id(&ownership, &wwd_fr)?;

    Ok(TributeOwnership {
        nonce: fr_to_bytes(&nonce),
        ownership: fr_to_bytes(&ownership),
        tribute_draft_id: fr_to_bytes(&tribute_draft_id),
    })
}

// -- 2. Prove SpendingUnit ownership --

/// Generate an ownership-only proof for a SpendingUnit.
///
/// The nonce and ID are provided by the SRA server that generated the SU.
#[uniffi::export]
pub fn prove_spending_unit_ownership(
    secret_key: Vec<u8>,
    spending_unit: SpendingUnitInput,
) -> Result<ProofResult, MobileError> {
    let sk = parse_secret_key(&secret_key)?;
    let nonce = bytes_to_fr(&spending_unit.nonce)?;
    let su = build_spending_unit(&sk, nonce, &spending_unit)?;

    let witness = build_ownership_witness(
        &su,
        OwnershipWitnessCtx {
            secret_key: &sk,
            nonce,
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
) -> Result<ProofResult, MobileError> {
    let sk = parse_secret_key(&secret_key)?;
    let nonce_fr = bytes_to_fr(&nonce)?;
    let td = build_tribute_draft(&sk, nonce_fr, &tribute)?;

    let witness = build_ownership_witness(
        &td,
        OwnershipWitnessCtx {
            secret_key: &sk,
            nonce: nonce_fr,
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
) -> Result<ProofResult, MobileError> {
    let sk = parse_secret_key(&secret_key)?;
    let nonce = bytes_to_fr(&spending_unit.nonce)?;
    let su = build_spending_unit(&sk, nonce, &spending_unit)?;
    let path = parse_merkle_path(&merkle_path)?;

    let witness = build_full_proof_witness(
        &su,
        FullProofWitnessCtx {
            secret_key: &sk,
            nonce,
            merkle_path: &path,
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
) -> Result<ProofResult, MobileError> {
    let sk = parse_secret_key(&secret_key)?;
    let nonce_fr = bytes_to_fr(&nonce)?;
    let td = build_tribute_draft(&sk, nonce_fr, &tribute)?;
    let path = parse_merkle_path(&merkle_path)?;

    let witness = build_full_proof_witness(
        &td,
        FullProofWitnessCtx {
            secret_key: &sk,
            nonce: nonce_fr,
            merkle_path: &path,
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
    sk: &k256::elliptic_curve::SecretKey<k256::Secp256k1>,
    nonce: Fr,
    input: &SpendingUnitInput,
) -> Result<pso_nft::SpendingUnit, MobileError> {
    let id = bytes_to_fr(&input.id)?;
    let date = parse_worldwide_day(input.worldwide_day)?;
    let currency = parse_currency(input.settlement_currency)?;
    let sr_fps = bytes_vec_to_fr_vec(&input.spending_records_fingerprints)?;
    let ar_fps = bytes_vec_to_fr_vec(&input.amendment_records_fingerprints)?;

    let ownership =
        pso_integrations_shared::witness::ownership_from_public_key(&sk.public_key(), nonce)
            .map_err(|e| MobileError::Internal {
                detail: e.to_string(),
            })?;

    Ok(pso_nft::SpendingUnit {
        id,
        owner: ownership,
        settlement_currency: currency,
        settlement_amount_base: input.settlement_amount_base,
        settlement_amount_atto: input.settlement_amount_atto,
        worldwide_day: date,
        spending_records_fingerprints: sr_fps,
        amendment_records_fingerprints: ar_fps,
    })
}

/// Build a `pso_nft::TributeDraft` from FFI inputs.
fn build_tribute_draft(
    sk: &k256::elliptic_curve::SecretKey<k256::Secp256k1>,
    nonce: Fr,
    input: &TributeInput,
) -> Result<pso_nft::TributeDraft, MobileError> {
    let date = parse_worldwide_day(input.worldwide_day)?;
    let currency = parse_currency(input.settlement_currency)?;
    let su_ids = bytes_vec_to_fr_vec(&input.su_ids)?;
    let wwd = worldwide_day_count(&date);
    let wwd_fr = Fr::from(wwd);

    let ownership =
        pso_integrations_shared::witness::ownership_from_public_key(&sk.public_key(), nonce)
            .map_err(|e| MobileError::Internal {
                detail: e.to_string(),
            })?;

    let id = compute_tribute_draft_id(&ownership, &wwd_fr)?;

    Ok(pso_nft::TributeDraft {
        id,
        owner: ownership,
        settlement_currency: currency,
        settlement_amount_base: input.settlement_amount_base,
        settlement_amount_atto: input.settlement_amount_atto,
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
#[uniffi::export]
pub fn prove_su_ownership_aggregation(
    secret_key: Vec<u8>,
    su_slots: Vec<SuAggregationSlot>,
    sender: Vec<u8>,
    tribute_draft_id: Vec<u8>,
    chain_id: u64,
) -> Result<ProofResult, MobileError> {
    use pso_integrations_shared::witness::{
        generate_aggregation_witness, AggregationSlot as CoreSlot, AggregationWitnessCtx,
    };

    if sender.len() != 20 {
        return Err(MobileError::Internal {
            detail: format!("sender must be 20 bytes, got {}", sender.len()),
        });
    }
    if tribute_draft_id.len() != 32 {
        return Err(MobileError::Internal {
            detail: format!(
                "tribute_draft_id must be 32 bytes, got {}",
                tribute_draft_id.len()
            ),
        });
    }

    let sk = parse_secret_key(&secret_key)?;

    // Resolve tier (n=0 and n>64 both rejected here).
    let tier =
        pso_zk_canonical::select_aggregation_tier(su_slots.len() as u32).ok_or_else(|| {
            MobileError::AggregationTierUnavailable {
                detail: format!(
                    "no aggregation tier for n_su={} (must be 1..=64)",
                    su_slots.len()
                ),
            }
        })?;

    // Decode slots: (nonce, derived_owner) each as 32-byte LE Fr.
    let core_slots: Vec<CoreSlot> = su_slots
        .iter()
        .map(|s| {
            let nonce = bytes_to_fr(&s.nonce)?;
            let derived_owner = bytes_to_fr(&s.derived_owner)?;
            Ok(CoreSlot {
                nonce,
                derived_owner,
            })
        })
        .collect::<Result<_, MobileError>>()?;

    // Binding hash: Poseidon4(sender, tdid_lo, tdid_hi, chainid). The
    // splitting matches what the on-chain contract does via the
    // 0x0202 Poseidon precompile.
    let binding_hash = compute_binding_hash(&sender, &tribute_draft_id, chain_id)?;

    // Build witness.
    let witness = generate_aggregation_witness(AggregationWitnessCtx {
        secret_key: &sk,
        real_slots: &core_slots,
        tier_n: tier.tier_n,
        binding_hash,
    })
    .map_err(|e| MobileError::WitnessGenerationFailed {
        detail: e.to_string(),
    })?;

    // Prove.
    let circuit = circuits::su_aggregation_circuit(tier.tier_n)?;
    let proof = circuit
        .prove(&witness)
        .map_err(|e| MobileError::ProofFailed {
            detail: e.to_string(),
        })?;
    Ok(noir_proof_to_result(&proof))
}

/// Off-chain mirror of `TributeDraft._bindingHash`. Thin wrapper around
/// `pso_protocol::binding::compute_binding_hash` — the consensus-binding
/// formula lives there. We keep this wrapper to translate the slice
/// inputs (and `ProtocolError`) into the FFI shape.
fn compute_binding_hash(
    sender: &[u8],           // 20 bytes BE
    tribute_draft_id: &[u8], // 32 bytes BE
    chain_id: u64,
) -> Result<Fr, MobileError> {
    let sender_arr: &[u8; 20] = sender.try_into().map_err(|_| MobileError::Internal {
        detail: format!("sender must be 20 bytes, got {}", sender.len()),
    })?;
    let tdid_arr: &[u8; 32] = tribute_draft_id
        .try_into()
        .map_err(|_| MobileError::Internal {
            detail: format!(
                "tribute_draft_id must be 32 bytes, got {}",
                tribute_draft_id.len()
            ),
        })?;
    pso_protocol::binding::compute_binding_hash(sender_arr, tdid_arr, chain_id).map_err(|e| {
        MobileError::Internal {
            detail: e.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_secret_key() -> k256::SecretKey {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        k256::SecretKey::from_slice(&b).expect("random bytes should form a valid key")
    }

    #[test]
    fn test_compute_tribute_ownership_returns_valid_data() {
        let sk = random_secret_key();
        let result = compute_tribute_ownership(sk.to_bytes().to_vec(), 20260305).unwrap();
        assert_eq!(result.nonce.len(), 32);
        assert_eq!(result.ownership.len(), 32);
        assert_eq!(result.tribute_draft_id.len(), 32);
    }

    #[test]
    fn test_compute_tribute_ownership_different_nonces() {
        let sk = random_secret_key();
        let r1 = compute_tribute_ownership(sk.to_bytes().to_vec(), 20260305).unwrap();
        let r2 = compute_tribute_ownership(sk.to_bytes().to_vec(), 20260305).unwrap();
        // Nonces should differ (random)
        assert_ne!(r1.nonce, r2.nonce);
        // Ownership hashes should differ (different nonces)
        assert_ne!(r1.ownership, r2.ownership);
    }

    #[test]
    fn test_build_tribute_draft_id_matches_compute() {
        let sk = random_secret_key();
        let sk_bytes = sk.to_bytes().to_vec();

        let ownership_result = compute_tribute_ownership(sk_bytes.clone(), 20260305).unwrap();

        let nonce_fr = bytes_to_fr(&ownership_result.nonce).unwrap();
        let tribute_input = TributeInput {
            settlement_currency: 978,
            settlement_amount_base: 100,
            settlement_amount_atto: 0,
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
            settlement_currency: 978,
            settlement_amount_base: 50,
            settlement_amount_atto: 0,
            worldwide_day: 20260305,
            spending_records_fingerprints: vec![],
            amendment_records_fingerprints: vec![],
        };

        let su = build_spending_unit(&sk, nonce, &input).unwrap();
        assert_eq!(su.id, id);
        assert_eq!(su.settlement_amount_base, 50);
    }

    #[test]
    fn test_select_su_aggregation_tier_rounds_up() {
        let info = select_su_aggregation_tier(5).unwrap();
        assert_eq!(info.tier_n, 6, "5 SUs should fit the N=6 tier");
        assert_eq!(info.label, "pso.su_ownership_aggregation.n6");
        assert_eq!(info.circuit_hash.len(), 32);
        assert_eq!(info.vk_hash.len(), 32);
    }

    #[test]
    fn test_select_su_aggregation_tier_exact_match() {
        let info = select_su_aggregation_tier(8).unwrap();
        assert_eq!(info.tier_n, 8);
        assert_eq!(info.label, "pso.su_ownership_aggregation.n8");
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
        assert_eq!(sizes, vec![1, 2, 4, 6, 8, 16, 32, 64]);
    }

    #[test]
    fn test_prove_su_ownership_aggregation_end_to_end_n1() {
        // Smallest tier — fastest test. Full prove+verify against the
        // canonical VK exposed through the FFI surface.
        let sk = random_secret_key();

        let nonce = Fr::rand(&mut OsRng);
        let derived_owner =
            pso_integrations_shared::witness::ownership_from_public_key(&sk.public_key(), nonce)
                .unwrap();

        let slot = SuAggregationSlot {
            nonce: fr_to_bytes(&nonce),
            derived_owner: fr_to_bytes(&derived_owner),
        };

        let sender = vec![0x11u8; 20];
        let tribute_draft_id = vec![0x22u8; 32];
        let chain_id: u64 = 19_280_501;

        let result = prove_su_ownership_aggregation(
            sk.to_bytes().to_vec(),
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

        // Verify against the canonical VK via the same circuit instance.
        let circuit = crate::circuits::su_aggregation_circuit(1).unwrap();
        // Reconstruct a NoirProof from the FFI ProofResult.
        let noir_proof = pso_zk_circuit_noir::NoirProof {
            proof: result.proof,
            public_inputs: result.public_inputs,
        };
        let ok = circuit.verify(noir_proof).expect("verify must succeed");
        assert!(ok, "round trip: prove + verify against canonical VK");
    }

    #[test]
    fn test_prove_su_ownership_aggregation_rejects_zero_slots() {
        let sk = random_secret_key();
        let err = prove_su_ownership_aggregation(
            sk.to_bytes().to_vec(),
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
            })
            .collect();
        let err = prove_su_ownership_aggregation(
            sk.to_bytes().to_vec(),
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

    #[test]
    fn test_prove_su_ownership_aggregation_rejects_bad_sender_length() {
        let sk = random_secret_key();
        let slot = SuAggregationSlot {
            nonce: vec![0u8; 32],
            derived_owner: vec![0u8; 32],
        };
        let err = prove_su_ownership_aggregation(
            sk.to_bytes().to_vec(),
            vec![slot],
            vec![0x00u8; 19], // wrong length
            vec![0x00u8; 32],
            1,
        )
        .unwrap_err();
        assert!(matches!(err, MobileError::Internal { .. }));
    }
}
