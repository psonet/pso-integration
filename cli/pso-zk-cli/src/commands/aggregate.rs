//! Handler for the `proof aggregate` CLI command.
//!
//! Builds an SU-ownership aggregation proof for TributeDraft
//! submission. Reads an input JSON describing the wallet's secret key,
//! the per-SU `(nonce, derived_owner)` slots, and the binding-hash
//! parameters `(sender, tribute_draft_id, chain_id)`, then writes the
//! canonical proof bytes to the output file.
//!
//! Same on-chain semantics as `pso_mobile_integration::api::
//! prove_su_ownership_aggregation` — both call into pso-zk-core +
//! pso-zk-circuit-noir + pso-zk-canonical. This handler exists for
//! non-mobile environments (CI, server-side tooling) that need to
//! exercise the flow without UniFFI.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use k256::SecretKey;
use serde::{Deserialize, Serialize};

use pso_integrations_shared::witness::{
    generate_aggregation_witness, AggregationSlot, AggregationWitnessCtx,
};
use pso_zk_circuit_noir::{circuit_loader, NoirSuOwnershipAggregationCircuit};

use crate::display::{build_table, KeyValueRow};

/// Input JSON for `proof aggregate`.
///
/// All hex fields accept optional `0x` prefix.
#[derive(Debug, Deserialize)]
pub struct AggregationInput {
    /// 32-byte secp256k1 secret key (little-endian).
    pub secret_key_hex: String,
    /// One entry per SU being aggregated.
    pub slots: Vec<AggregationInputSlot>,
    /// 20-byte EVM address — the on-chain `msg.sender` at submit time.
    pub sender_hex: String,
    /// 32-byte uint256 (big-endian) — the TributeDraft id being submitted.
    pub tribute_draft_id_hex: String,
    /// L2 chain id (`block.chainid` on the contract side).
    pub chain_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct AggregationInputSlot {
    /// 32-byte little-endian Fr nonce used at SU mint time.
    pub nonce_hex: String,
    /// 32-byte little-endian Fr `derived_owner` value as stored at
    /// `SpendingUnit.derivedOwner` on-chain.
    pub derived_owner_hex: String,
}

/// JSON shape written to the output file.
#[derive(Debug, Serialize, Deserialize)]
pub struct AggregationProofOutput {
    /// Tier the resolver selected for this aggregation.
    pub tier_n: u32,
    /// Canonical circuit_hash (matches the on-chain `_selectTier` constant).
    pub circuit_hash_hex: String,
    /// Hex-encoded combined proof: `[num_inputs:4B BE][public_inputs:32B*K][proof]`.
    /// Wallets feed this directly to `TributeDraft.submit`'s
    /// `aggregationProof` calldata.
    pub combined_proof_hex: String,
    /// Public inputs decoded for debugging (each 32 bytes, big-endian).
    pub public_inputs_hex: Vec<String>,
}

/// Run the `proof aggregate` command end-to-end.
pub fn handle_proof_aggregate(input_path: &Path, output_path: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(input_path)
        .with_context(|| format!("read aggregation input {}", input_path.display()))?;
    let input: AggregationInput = serde_json::from_str(&raw)
        .with_context(|| format!("parse aggregation input {}", input_path.display()))?;

    // Decode bytes.
    let sk_bytes = parse_hex_32(&input.secret_key_hex, "secret_key")?;
    let sk = SecretKey::from_slice(&sk_bytes).context("invalid secret_key")?;

    let sender = parse_hex_n(&input.sender_hex, 20, "sender")?;
    let tribute_draft_id = parse_hex_n(&input.tribute_draft_id_hex, 32, "tribute_draft_id")?;
    let chain_id = input.chain_id;

    // Decode slots.
    let slots: Vec<AggregationSlot> = input
        .slots
        .iter()
        .map(|s| {
            let nonce = Fr::from_le_bytes_mod_order(&parse_hex_32(&s.nonce_hex, "slot.nonce")?);
            let derived_owner = Fr::from_le_bytes_mod_order(&parse_hex_32(
                &s.derived_owner_hex,
                "slot.derived_owner",
            )?);
            Ok(AggregationSlot {
                nonce,
                derived_owner,
            })
        })
        .collect::<Result<_>>()?;

    if slots.is_empty() {
        bail!("aggregation input must contain at least one slot");
    }

    // Resolve tier.
    let tier = pso_zk_canonical::select_aggregation_tier(slots.len() as u32).ok_or_else(|| {
        anyhow!(
            "no aggregation tier for n_su={} (must be 1..=64)",
            slots.len()
        )
    })?;

    // Binding hash.
    let binding_hash = compute_binding_hash(&sender, &tribute_draft_id, chain_id)?;

    // Witness + circuit + prove.
    let witness = generate_aggregation_witness(AggregationWitnessCtx {
        secret_key: &sk,
        real_slots: &slots,
        tier_n: tier.tier_n,
        binding_hash,
    })?;

    let bytecode = circuit_loader::load_circuit_from_str(load_circuit_json(tier.tier_n)?)?;
    let circuit = NoirSuOwnershipAggregationCircuit::new(
        bytecode.bytecode,
        tier.tier_n,
        tier.descriptor.vk_bytes.to_vec(),
    )?;
    let proof = circuit.prove(&witness)?;

    // Recombine into the on-chain calldata shape.
    let combined = proof.to_combined();

    // Console summary.
    let rows = vec![
        KeyValueRow {
            field: "tier_n".to_string(),
            value: tier.tier_n.to_string(),
        },
        KeyValueRow {
            field: "circuit".to_string(),
            value: tier.descriptor.label.to_string(),
        },
        KeyValueRow {
            field: "circuit_hash".to_string(),
            value: hex32(&tier.descriptor.circuit_hash),
        },
        KeyValueRow {
            field: "vk_hash".to_string(),
            value: hex32(&tier.descriptor.vk_hash),
        },
        KeyValueRow {
            field: "proof_bytes".to_string(),
            value: combined.len().to_string(),
        },
        KeyValueRow {
            field: "public_inputs".to_string(),
            value: proof.public_inputs.len().to_string(),
        },
    ];
    println!("Aggregation proof:\n{}", build_table(&rows));

    // Output JSON.
    let output = AggregationProofOutput {
        tier_n: tier.tier_n,
        circuit_hash_hex: hex32(&tier.descriptor.circuit_hash),
        combined_proof_hex: format!("0x{}", hex::encode(&combined)),
        public_inputs_hex: proof
            .public_inputs
            .iter()
            .map(|pi| format!("0x{}", hex::encode(pi)))
            .collect(),
    };

    let serialized = serde_json::to_string_pretty(&output)?;
    std::fs::write(output_path, serialized)
        .with_context(|| format!("write proof {}", output_path.display()))?;
    println!("Wrote proof to {}", output_path.display());
    Ok(())
}

fn load_circuit_json(tier_n: u32) -> Result<&'static str> {
    Ok(match tier_n {
        1 => include_str!(
            "../../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n1.json"
        ),
        2 => include_str!(
            "../../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n2.json"
        ),
        4 => include_str!(
            "../../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n4.json"
        ),
        6 => include_str!(
            "../../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n6.json"
        ),
        8 => include_str!(
            "../../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n8.json"
        ),
        16 => include_str!(
            "../../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n16.json"
        ),
        32 => include_str!(
            "../../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n32.json"
        ),
        64 => include_str!(
            "../../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n64.json"
        ),
        _ => bail!("unsupported aggregation tier_n={tier_n}"),
    })
}

/// Thin wrapper around `pso_protocol::binding::compute_binding_hash`.
/// The consensus-binding formula lives in pso-protocol; this CLI handler
/// only needs to translate slice inputs into the fixed-size arrays the
/// protocol API requires.
fn compute_binding_hash(sender: &[u8], tribute_draft_id: &[u8], chain_id: u64) -> Result<Fr> {
    let sender_arr: &[u8; 20] = sender
        .try_into()
        .map_err(|_| anyhow!("sender must be 20 bytes, got {}", sender.len()))?;
    let tdid_arr: &[u8; 32] = tribute_draft_id.try_into().map_err(|_| {
        anyhow!(
            "tribute_draft_id must be 32 bytes, got {}",
            tribute_draft_id.len()
        )
    })?;
    pso_protocol::binding::compute_binding_hash(sender_arr, tdid_arr, chain_id)
        .map_err(|e| anyhow!("compute_binding_hash: {e}"))
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(trimmed).map_err(|e| anyhow!("hex decode: {e}"))
}

fn parse_hex_n(s: &str, n: usize, field: &str) -> Result<Vec<u8>> {
    let bytes = parse_hex(s)?;
    if bytes.len() != n {
        bail!("{field} must be {n} bytes, got {}", bytes.len());
    }
    Ok(bytes)
}

fn parse_hex_32(s: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex_n(s, 32, field)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use tempfile::tempdir;

    fn random_secret_key() -> SecretKey {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        SecretKey::from_slice(&b).unwrap()
    }

    fn fr_hex(f: &Fr) -> String {
        format!(
            "0x{}",
            hex::encode(pso_integrations_shared::witness::fr_to_le32(f))
        )
    }

    #[test]
    fn handle_proof_aggregate_writes_well_formed_output() {
        // End-to-end CLI: real key, one real slot, generates a proof
        // file the on-chain TD contract would accept.
        let sk = random_secret_key();
        let nonce = Fr::rand(&mut OsRng);
        let derived_owner =
            pso_integrations_shared::witness::ownership_from_public_key(&sk.public_key(), nonce)
                .unwrap();

        let input = AggregationInput {
            secret_key_hex: format!("0x{}", hex::encode(sk.to_bytes())),
            slots: vec![AggregationInputSlot {
                nonce_hex: fr_hex(&nonce),
                derived_owner_hex: fr_hex(&derived_owner),
            }],
            sender_hex: format!("0x{}", hex::encode([0x11u8; 20])),
            tribute_draft_id_hex: format!("0x{}", hex::encode([0x22u8; 32])),
            chain_id: 19_280_501,
        };

        let dir = tempdir().unwrap();
        let in_path = dir.path().join("input.json");
        let out_path = dir.path().join("proof.json");

        // `AggregationInput` is Deserialize-only; for the test we
        // serialise via serde_json::Value rather than re-deriving
        // Serialize on the input type.
        let v = serde_json::json!({
            "secret_key_hex": input.secret_key_hex,
            "slots": [{
                "nonce_hex": input.slots[0].nonce_hex,
                "derived_owner_hex": input.slots[0].derived_owner_hex,
            }],
            "sender_hex": input.sender_hex,
            "tribute_draft_id_hex": input.tribute_draft_id_hex,
            "chain_id": input.chain_id,
        });
        std::fs::write(&in_path, serde_json::to_string_pretty(&v).unwrap()).unwrap();

        handle_proof_aggregate(&in_path, &out_path).unwrap();

        let written = std::fs::read_to_string(&out_path).unwrap();
        let parsed: AggregationProofOutput = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed.tier_n, 1);
        assert_eq!(parsed.public_inputs_hex.len(), 2);
        assert!(parsed.combined_proof_hex.starts_with("0x"));
    }

    #[test]
    fn handle_proof_aggregate_rejects_oversized_slot_count() {
        let sk = random_secret_key();
        let slot = AggregationInputSlot {
            nonce_hex: format!("0x{}", hex::encode([0u8; 32])),
            derived_owner_hex: format!("0x{}", hex::encode([0u8; 32])),
        };
        let many: Vec<serde_json::Value> = (0..65)
            .map(|_| {
                serde_json::json!({
                    "nonce_hex": slot.nonce_hex,
                    "derived_owner_hex": slot.derived_owner_hex,
                })
            })
            .collect();

        let v = serde_json::json!({
            "secret_key_hex": format!("0x{}", hex::encode(sk.to_bytes())),
            "slots": many,
            "sender_hex": format!("0x{}", hex::encode([0u8; 20])),
            "tribute_draft_id_hex": format!("0x{}", hex::encode([0u8; 32])),
            "chain_id": 1,
        });
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("input.json");
        let out_path = dir.path().join("proof.json");
        std::fs::write(&in_path, serde_json::to_string(&v).unwrap()).unwrap();

        let err = handle_proof_aggregate(&in_path, &out_path).unwrap_err();
        assert!(
            err.to_string().contains("no aggregation tier"),
            "expected tier-unavailable error, got: {err}"
        );
    }
}
