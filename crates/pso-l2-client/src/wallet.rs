//! Wallet-side flow functions.
//!
//! Three layers of work happen here:
//!
//! 1. **Prepare** — wallet picks a nonce, computes the Poseidon5
//!    `derivedOwner` commitment, returns a [`SuOwnershipRecord`]. The
//!    `derivedOwner` is sent to the SRA via a secure channel; the
//!    nonce stays on the wallet.
//!
//! 2. **Aggregate** — given N [`SuOwnershipRecord`]s and the wallet's
//!    secret key, build the aggregation witness, prove it against the
//!    smallest covering tier circuit, and serialize the result into an
//!    [`AggregationProofBundle`] ready for `TributeDraft.submit`.
//!
//! 3. **Submit** — broadcast the actual `TributeDraft.submit(...)`
//!    transaction on L2.
//!
//! Plus [`generate_full_proof`] for the post-mint ownership-plus-
//! Merkle-inclusion proof wallets keep for later redemption.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

use alloy::primitives::{Bytes, FixedBytes, TxHash, U256};
use alloy::signers::local::PrivateKeySigner;

use once_cell::sync::OnceCell;
use pso_integrations_shared::witness::{
    build_full_proof_witness, fr_to_le32, generate_aggregation_witness, ownership_from_secret_key,
    AggregationSlot, AggregationWitnessCtx, FullProofWitnessCtx,
};
use pso_protocol::merkle::{MerklePathElement, MerklePathElementIndex};
use pso_protocol::witness::{HashableNFT, OwnableNFT};
use pso_zk_circuit_noir::{
    circuit_loader, NoirCircuitConfig, NoirFullProofCircuit, NoirSuOwnershipAggregationCircuit,
    ZKCircuit, ZKMode,
};
use serde::{Deserialize, Serialize};

use crate::abi::{ITributeDraft, TRIBUTE_DRAFT};
use crate::artifacts::{
    AggregationProofBundle, AggregationTier, FullProofBundle, SuOwnershipRecord,
};
use crate::client::L2Client;
use crate::error::L2ClientError;

// --------------------------------------------------------------------- //
// Embedded circuit ACIRs.
//
// These paths assume the sibling-repo dev layout: pso-integration and
// pso-zk-circuits both live under `~/.../psonet/`. Once
// `pso-zk-circuit-noir` exposes its ACIR data as `pub const`s, switch
// to those — the path-relative include_str! breaks for users who
// clone pso-integration without also having pso-zk-circuits on disk.
// --------------------------------------------------------------------- //

const FULL_PROOF_JSON: &str =
    include_str!("../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/full_proof.json");
const AGG_N1_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n1.json"
);
const AGG_N2_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n2.json"
);
const AGG_N4_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n4.json"
);
const AGG_N6_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n6.json"
);
const AGG_N8_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n8.json"
);
const AGG_N16_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n16.json"
);
const AGG_N32_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n32.json"
);
const AGG_N64_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n64.json"
);

static FULL_PROOF_CIRCUIT: OnceCell<NoirFullProofCircuit> = OnceCell::new();
static AGG_CIRCUIT_N1: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGG_CIRCUIT_N2: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGG_CIRCUIT_N4: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGG_CIRCUIT_N6: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGG_CIRCUIT_N8: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGG_CIRCUIT_N16: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGG_CIRCUIT_N32: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGG_CIRCUIT_N64: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();

fn init_agg_circuit(
    json: &str,
    tier_n: u32,
    vk_bytes: &'static [u8],
) -> Result<NoirSuOwnershipAggregationCircuit, L2ClientError> {
    let bytecode = circuit_loader::load_circuit_from_str(json)
        .map_err(|e| L2ClientError::Prover(format!("load tier {tier_n} ACIR: {e}")))?;
    NoirSuOwnershipAggregationCircuit::new(bytecode.bytecode, tier_n, vk_bytes.to_vec())
        .map_err(|e| L2ClientError::Prover(format!("init tier {tier_n}: {e}")))
}

fn aggregation_circuit_for(
    tier_n: u32,
) -> Result<&'static NoirSuOwnershipAggregationCircuit, L2ClientError> {
    use pso_zk_canonical as zk;
    match tier_n {
        1 => AGG_CIRCUIT_N1.get_or_try_init(|| {
            init_agg_circuit(AGG_N1_JSON, 1, zk::SU_OWNERSHIP_AGGREGATION_N1.vk_bytes)
        }),
        2 => AGG_CIRCUIT_N2.get_or_try_init(|| {
            init_agg_circuit(AGG_N2_JSON, 2, zk::SU_OWNERSHIP_AGGREGATION_N2.vk_bytes)
        }),
        4 => AGG_CIRCUIT_N4.get_or_try_init(|| {
            init_agg_circuit(AGG_N4_JSON, 4, zk::SU_OWNERSHIP_AGGREGATION_N4.vk_bytes)
        }),
        6 => AGG_CIRCUIT_N6.get_or_try_init(|| {
            init_agg_circuit(AGG_N6_JSON, 6, zk::SU_OWNERSHIP_AGGREGATION_N6.vk_bytes)
        }),
        8 => AGG_CIRCUIT_N8.get_or_try_init(|| {
            init_agg_circuit(AGG_N8_JSON, 8, zk::SU_OWNERSHIP_AGGREGATION_N8.vk_bytes)
        }),
        16 => AGG_CIRCUIT_N16.get_or_try_init(|| {
            init_agg_circuit(AGG_N16_JSON, 16, zk::SU_OWNERSHIP_AGGREGATION_N16.vk_bytes)
        }),
        32 => AGG_CIRCUIT_N32.get_or_try_init(|| {
            init_agg_circuit(AGG_N32_JSON, 32, zk::SU_OWNERSHIP_AGGREGATION_N32.vk_bytes)
        }),
        64 => AGG_CIRCUIT_N64.get_or_try_init(|| {
            init_agg_circuit(AGG_N64_JSON, 64, zk::SU_OWNERSHIP_AGGREGATION_N64.vk_bytes)
        }),
        _ => Err(L2ClientError::AggregationTierUnavailable {
            detail: format!("no aggregation circuit for tier_n={tier_n}"),
        }),
    }
}

fn full_proof_circuit() -> Result<&'static NoirFullProofCircuit, L2ClientError> {
    FULL_PROOF_CIRCUIT.get_or_try_init(|| {
        let bytecode = circuit_loader::load_circuit_from_str(FULL_PROOF_JSON)
            .map_err(|e| L2ClientError::Prover(format!("load full_proof ACIR: {e}")))?;
        let cfg = NoirCircuitConfig {
            circuit: bytecode,
            version: "0.0.1",
            low_memory: true,
            scheme: ZKMode::UltraHonkKeccak,
        };
        NoirFullProofCircuit::setup(cfg)
            .map_err(|e| L2ClientError::Prover(format!("setup full_proof: {e}")))
    })
}

// --------------------------------------------------------------------- //
// 1. Prepare — compute (nonce, derivedOwner) for a future SU.
// --------------------------------------------------------------------- //

/// Roll a fresh nonce and compute the wallet's `derivedOwner` for one
/// upcoming SU. The wallet sends `derived_owner` to the SRA so it can
/// mint a SpendingUnit; the wallet stores the entire
/// [`SuOwnershipRecord`] locally for later aggregation.
///
/// `su_id` is the (off-chain agreed-upon) id the SRA will mint the SU
/// under. The wallet must keep it bundled with the (nonce, owner)
/// pair so it can later assemble an aggregation request.
pub fn prepare_su_ownership(
    secret_key_bytes: &[u8; 32],
    su_id: U256,
) -> Result<SuOwnershipRecord, L2ClientError> {
    let sk = k256::SecretKey::from_slice(secret_key_bytes)
        .map_err(|e| L2ClientError::InvalidInput(format!("secret key: {e}")))?;
    let nonce = Fr::rand(&mut OsRng);
    let derived_owner =
        ownership_from_secret_key(&sk, nonce).map_err(|e| L2ClientError::Witness(e.to_string()))?;

    Ok(SuOwnershipRecord {
        su_id: format!("0x{:064x}", su_id),
        nonce: format!("0x{}", hex::encode(fr_to_le32(&nonce))),
        derived_owner: format!("0x{}", hex::encode(fr_to_le32(&derived_owner))),
    })
}

// --------------------------------------------------------------------- //
// 2. Aggregate — fold N [`SuOwnershipRecord`]s into one proof.
// --------------------------------------------------------------------- //

/// Inputs to [`aggregate_ownership`].
#[derive(Debug, Clone)]
pub struct AggregateInputs<'a> {
    /// Wallet's signing key (32-byte secp256k1 scalar).
    pub secret_key: &'a [u8; 32],
    /// Per-SU ownership records the wallet stored at `prepare` time.
    /// Length must be ≥ 1; the smallest tier covering this count is
    /// selected automatically.
    pub records: &'a [SuOwnershipRecord],
    /// The on-chain SU ids the wallet will declare in
    /// `TributeDraft.submit`'s `suIds` argument. Must be parallel to
    /// `records` (`su_ids[i]` corresponds to `records[i]`).
    pub su_ids: &'a [U256],
    /// TributeDraft id the wallet is about to mint.
    pub tribute_draft_id: U256,
    /// EVM chain id of the L2 the proof targets.
    pub chain_id: u64,
}

/// Build the SU-ownership aggregation proof a wallet attaches to
/// `TributeDraft.submit` as the `aggregationProof` calldata.
///
/// Slow path — runs the Noir prover. Wallets should call on a
/// background thread. Mobile wallets get the equivalent surface via
/// `pso_mobile_integration::api::prove_su_ownership_aggregation`.
pub fn aggregate_ownership(
    inputs: AggregateInputs<'_>,
) -> Result<AggregationProofBundle, L2ClientError> {
    if inputs.records.len() != inputs.su_ids.len() {
        return Err(L2ClientError::InvalidInput(format!(
            "records.len ({}) != su_ids.len ({})",
            inputs.records.len(),
            inputs.su_ids.len()
        )));
    }
    if inputs.records.is_empty() {
        return Err(L2ClientError::InvalidInput(
            "at least one ownership record required".into(),
        ));
    }

    let sk = k256::SecretKey::from_slice(inputs.secret_key)
        .map_err(|e| L2ClientError::InvalidInput(format!("secret key: {e}")))?;
    // Derive the EVM address the wallet will broadcast from — same
    // address `msg.sender` resolves to inside `TributeDraft.submit`.
    let sender_evm: [u8; 20] = PrivateKeySigner::from_slice(inputs.secret_key)
        .map_err(|e| L2ClientError::InvalidInput(format!("signer: {e}")))?
        .address()
        .into_array();

    let tier_desc = pso_zk_canonical::select_aggregation_tier(inputs.records.len() as u32)
        .ok_or_else(|| L2ClientError::AggregationTierUnavailable {
            detail: format!(
                "no tier for n_su={} (supported: 1, 2, 4, 6, 8, 16, 32, 64)",
                inputs.records.len()
            ),
        })?;

    // Decode (nonce, derived_owner) pairs.
    let mut real_slots: Vec<AggregationSlot> = Vec::with_capacity(inputs.records.len());
    for rec in inputs.records {
        let nonce_bytes = decode_hex_le32(&rec.nonce)?;
        let owner_bytes = decode_hex_le32(&rec.derived_owner)?;
        real_slots.push(AggregationSlot {
            nonce: ark_ff::PrimeField::from_le_bytes_mod_order(&nonce_bytes),
            derived_owner: ark_ff::PrimeField::from_le_bytes_mod_order(&owner_bytes),
        });
    }

    // Binding hash binds the proof to (sender, tdid, chainid). Use
    // U256's big-endian byte view so the limb decomposition inside
    // pso-protocol::binding matches what TributeDraft.sol does on-chain.
    let tdid_be: [u8; 32] = inputs.tribute_draft_id.to_be_bytes();
    let binding_hash =
        pso_protocol::binding::compute_binding_hash(&sender_evm, &tdid_be, inputs.chain_id)?;

    let witness = generate_aggregation_witness(AggregationWitnessCtx {
        secret_key: &sk,
        real_slots: &real_slots,
        tier_n: tier_desc.tier_n,
        binding_hash,
    })
    .map_err(|e| L2ClientError::Witness(e.to_string()))?;

    let circuit = aggregation_circuit_for(tier_desc.tier_n)?;
    let proof = circuit
        .prove(&witness)
        .map_err(|e| L2ClientError::Prover(e.to_string()))?;
    let combined = proof.to_combined();

    // TD-level derivedOwner — wallet picks a fresh nonce so the TD
    // commitment is unlinkable from individual SUs.
    let td_nonce = Fr::rand(&mut OsRng);
    let td_derived_owner = ownership_from_secret_key(&sk, td_nonce)
        .map_err(|e| L2ClientError::Witness(e.to_string()))?;

    Ok(AggregationProofBundle {
        tribute_draft_id: format!("0x{:064x}", inputs.tribute_draft_id),
        td_derived_owner: format!("0x{}", hex::encode(fr_to_le32(&td_derived_owner))),
        su_ids: inputs
            .su_ids
            .iter()
            .map(|id| format!("0x{:064x}", id))
            .collect(),
        tier: AggregationTier {
            tier_n: tier_desc.tier_n,
            label: tier_desc.descriptor.label.to_string(),
            circuit_hash: format!("0x{}", hex::encode(tier_desc.descriptor.circuit_hash)),
        },
        proof_bytes_hex: format!("0x{}", hex::encode(&combined)),
    })
}

// --------------------------------------------------------------------- //
// 3. Submit — broadcast `TributeDraft.submit(...)`.
// --------------------------------------------------------------------- //

/// Submit a TributeDraft on L2 using a previously-built
/// [`AggregationProofBundle`].
///
/// Returns the broadcast transaction hash. Caller can poll for receipt
/// via the alloy provider if they need to confirm inclusion.
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

// --------------------------------------------------------------------- //
// 4. Full proof — post-mint ownership + Merkle inclusion artifact.
// --------------------------------------------------------------------- //

/// Per-TD record the wallet supplies when generating a full proof.
/// Mirrors `pso_nft::TributeDraft`'s hashable surface but doesn't
/// require depending on `pso-nft` from here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullProofTributeDraft {
    /// TD id (hex string with `0x` prefix).
    pub tribute_draft_id: String,
    /// Wallet's `derivedOwner` for this TD.
    pub td_derived_owner: String,
    /// TD-level nonce — the value `td_derived_owner = Poseidon5(pk, nonce)`.
    pub td_nonce: String,
    /// ISO 4217 currency numeric code.
    pub settlement_currency: u16,
    /// Worldwide-day count.
    pub worldwide_day: u64,
    /// Settlement amount integer part.
    pub settlement_amount_base: u64,
    /// Settlement amount fractional part (atto).
    pub settlement_amount_atto: u64,
    /// SU ids the TD aggregates over (hex strings).
    pub su_ids: Vec<String>,
}

/// Generate the ownership + Merkle inclusion proof for an already-minted
/// TD. Wallets keep this for later redemption / audit; it isn't fed
/// back to L2 by any current contract path.
pub fn generate_full_proof(
    secret_key_bytes: &[u8; 32],
    td: &FullProofTributeDraft,
    merkle_path: &[MerklePathElementInput],
) -> Result<FullProofBundle, L2ClientError> {
    let sk = k256::SecretKey::from_slice(secret_key_bytes)
        .map_err(|e| L2ClientError::InvalidInput(format!("secret key: {e}")))?;

    let nonce_bytes = decode_hex_le32(&td.td_nonce)?;
    let nonce = ark_ff::PrimeField::from_le_bytes_mod_order(&nonce_bytes);

    let owner_bytes = decode_hex_le32(&td.td_derived_owner)?;
    let owner = ark_ff::PrimeField::from_le_bytes_mod_order(&owner_bytes);

    let su_ids: Vec<Fr> = td
        .su_ids
        .iter()
        .map(|s| {
            let bytes = decode_hex_le32(s)?;
            Ok(ark_ff::PrimeField::from_le_bytes_mod_order(&bytes))
        })
        .collect::<Result<Vec<_>, L2ClientError>>()?;

    let td_id_fr = pso_protocol::nft::compute_tribute_draft_id(&owner, td.worldwide_day)?;
    let entity_hash = pso_protocol::nft::compute_tribute_draft_hash(
        &td_id_fr,
        td.settlement_currency,
        td.settlement_amount_base,
        td.settlement_amount_atto,
        &su_ids,
    )?;

    let nft = TdNft { owner, entity_hash };

    let path: Vec<MerklePathElement> = merkle_path
        .iter()
        .map(|el| {
            let bytes = decode_hex_le32(&el.node_hash)?;
            let index = match el.index {
                0 => MerklePathElementIndex::Skip,
                1 => MerklePathElementIndex::Left,
                2 => MerklePathElementIndex::Right,
                other => {
                    return Err(L2ClientError::InvalidInput(format!(
                        "merkle path index must be 0/1/2, got {other}"
                    )))
                }
            };
            Ok(MerklePathElement {
                node_hash: bytes,
                index,
            })
        })
        .collect::<Result<Vec<_>, L2ClientError>>()?;

    let witness = build_full_proof_witness(
        &nft,
        FullProofWitnessCtx {
            secret_key: &sk,
            nonce,
            merkle_path: &path,
        },
    )
    .map_err(|e| L2ClientError::Witness(e.to_string()))?;

    let circuit = full_proof_circuit()?;
    let proof = circuit
        .prove(witness)
        .map_err(|e| L2ClientError::Prover(e.to_string()))?;

    let public_inputs_hex: Vec<String> = proof
        .public_inputs
        .iter()
        .map(|p| format!("0x{}", hex::encode(p)))
        .collect();
    let proof_bytes_hex = format!("0x{}", hex::encode(&proof.proof));

    Ok(FullProofBundle {
        tribute_draft_id: td.tribute_draft_id.clone(),
        circuit_label: "pso.full_proof".to_string(),
        public_inputs: public_inputs_hex,
        proof_bytes_hex,
    })
}

/// One element of a Merkle inclusion path. Hex `node_hash` + 0/1/2
/// index per `MerklePathElementIndex`. Same shape as the FFI surface
/// in `pso_mobile_integration::types::MerklePathElementInput`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePathElementInput {
    /// Sibling node hash (32-byte LE Fr, hex-encoded with `0x` prefix).
    pub node_hash: String,
    /// Position index: 0 = Skip, 1 = Left, 2 = Right.
    pub index: u8,
}

// --------------------------------------------------------------------- //
// Helpers
// --------------------------------------------------------------------- //

struct TdNft {
    owner: Fr,
    entity_hash: Fr,
}

impl OwnableNFT for TdNft {
    fn ownership(&self) -> Fr {
        self.owner
    }
}

impl HashableNFT for TdNft {
    fn hash(&self) -> Result<Fr, pso_protocol::ProtocolError> {
        Ok(self.entity_hash)
    }
}

fn parse_uint256(s: &str) -> Result<U256, L2ClientError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| L2ClientError::InvalidInput(format!("hex: {e}")))?;
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
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| L2ClientError::InvalidInput(format!("hex: {e}")))?;
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
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| L2ClientError::InvalidInput(format!("hex: {e}")))
}

fn decode_hex_le32(s: &str) -> Result<[u8; 32], L2ClientError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| L2ClientError::InvalidInput(format!("hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(L2ClientError::InvalidInput(format!(
            "expected 32-byte hex, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
