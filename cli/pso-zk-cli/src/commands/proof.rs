//! Handlers for the `proof generate` and `proof verify` CLI commands.
//!
//! `proof generate` reads an NFT JSON file (from `nft generate`),
//! reconstructs the entity + signer, and produces an **ownership** proof
//! against the canonical `OwnershipProof` circuit via the Barretenberg
//! backend.
//!
//! `proof verify` reads a proof JSON file and verifies it against the
//! same circuit.
//!
//! NOTE: the pre-0.8 CLI also offered a "full" mode (ownership + Merkle
//! inclusion) backed by `pso-zk-circuit-noir`'s `NoirFullProofCircuit`.
//! The new `pso-zk-canonical` surface exposes the ownership circuit (and
//! the flat-aggregation tiers); the standalone full-proof circuit is not
//! part of it, so only the ownership proof is produced here.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use rand::rngs::OsRng;
use rand::RngCore;

use pso_protocol::protocol::key::{NftSecret, Signer};
use pso_protocol::protocol::zk::{Circuit, ProofGenerator, ProofVerifier};
use pso_protocol::{Codec, PsoV1, Suite};
use pso_zk_backend::barretenberg::Barretenberg;
use pso_zk_canonical::noir::ownership_proof::{OwnershipProof, PublicInputs};
use pso_zk_canonical::ownership::Provable;

use crate::display::{build_table, KeyValueRow};
use crate::types::{GeneratedOutput, SerializableProof};

type Fr = <PsoV1 as Suite>::Field;

/// Handle the `proof generate` command. Reconstructs the entity +
/// signer from the NFT file, builds the ownership witness over the
/// redemption binding, runs the backend, and writes the proof.
pub fn handle_proof_generate(
    nft_path: &Path,
    output: &Path,
    redeemer: &[u8; 20],
    chain_id: u64,
) -> Result<()> {
    let content = std::fs::read_to_string(nft_path)
        .with_context(|| format!("Failed to read NFT file: {}", nft_path.display()))?;
    let gen: GeneratedOutput =
        serde_json::from_str(&content).context("Failed to parse NFT file as GeneratedOutput")?;

    // Reconstruct the signing key + nonce.
    let sk_bytes = hex::decode(&gen.secret_key_hex).context("decode secret_key_hex")?;
    let sk = PsoV1::secret_from_bytes(&sk_bytes).context("secret_from_bytes")?;
    let nonce_bytes: [u8; 32] = hex::decode(&gen.nonce_hex)
        .context("decode nonce_hex")?
        .try_into()
        .map_err(|_| anyhow!("nonce_hex must be 32 bytes"))?;
    let nonce = PsoV1::field_from_be32(&nonce_bytes);
    let signer = Signer::<PsoV1>::from_secret(NftSecret::new(sk), nonce)
        .context("bind signer to nonce")?;

    // The commitment the binding pins: the NFT id.
    let commitment_id: [u8; 32] = hex::decode(gen.nft_id.strip_prefix("0x").unwrap_or(&gen.nft_id))
        .context("decode nft_id")?
        .try_into()
        .map_err(|_| anyhow!("nft_id must be 32 bytes"))?;
    let binding = PsoV1::binding(redeemer, &commitment_id, chain_id).context("binding")?;

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut rng = StdRng::from_seed(seed);

    // Build the ownership witness from the entity (which carries the
    // matching `derivedOwner`), then prove.
    let (witness, public, circuit_hash) = match gen.nft_type.as_str() {
        "spending-unit" => {
            let entity = gen
                .spending_unit
                .clone()
                .ok_or_else(|| anyhow!("spending-unit body missing"))?
                .into_entity()?;
            let (w, p) = entity
                .derive_ownership_witness(&mut rng, &signer, binding)
                .context("derive ownership witness")?;
            (w, p, gen.nft_hash.clone())
        }
        "tribute-draft" => {
            let entity = gen
                .tribute_draft
                .clone()
                .ok_or_else(|| anyhow!("tribute-draft body missing"))?
                .into_entity()?;
            let (w, p) = entity
                .derive_ownership_witness(&mut rng, &signer, binding)
                .context("derive ownership witness")?;
            (w, p, gen.nft_hash.clone())
        }
        other => return Err(anyhow!("Unknown NFT type: {}", other)),
    };

    let backend = Barretenberg::default();
    let proof = ProofGenerator::<PsoV1, OwnershipProof>::generate(&backend, &witness, &public)
        .context("generate ownership proof")?;
    let public_inputs: Vec<String> = <OwnershipProof as Circuit<PsoV1>>::public_inputs(&public)
        .iter()
        .map(|f| format!("0x{}", hex::encode(PsoV1::field_to_be_bytes(f))))
        .collect();

    let serializable = SerializableProof {
        proof: proof
            .proof
            .iter()
            .map(|field| format!("0x{}", hex::encode(field)))
            .collect(),
        public_inputs,
        mode: "ownership".to_string(),
        circuit_hash,
    };
    let json = serde_json::to_string_pretty(&serializable).context("serialize proof")?;
    std::fs::write(output, &json)
        .with_context(|| format!("Failed to write proof file: {}", output.display()))?;

    let rows = vec![
        kv("Proof Mode", "ownership"),
        kv("Public Inputs", &serializable.public_inputs.len().to_string()),
        kv("Output File", &output.display().to_string()),
    ];
    println!("{}", build_table(&rows));
    Ok(())
}

/// Handle the `proof verify` command. Reconstructs the public inputs
/// from the proof JSON and verifies against the ownership circuit.
pub fn handle_proof_verify(proof_path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;
    let sp: SerializableProof =
        serde_json::from_str(&content).context("Failed to parse proof file")?;
    if sp.mode != "ownership" {
        return Err(anyhow!("Unknown proof mode: {}", sp.mode));
    }

    // Ownership public inputs are `[owner, nft_hash, binding_hash]`.
    let pi = sp
        .public_inputs
        .iter()
        .map(|s| {
            let b: [u8; 32] = hex::decode(s.strip_prefix("0x").unwrap_or(s))
                .context("decode public input")?
                .try_into()
                .map_err(|_| anyhow!("public input must be 32 bytes"))?;
            Ok::<Fr, anyhow::Error>(PsoV1::field_from_be32(&b))
        })
        .collect::<Result<Vec<_>>>()?;
    if pi.len() != 3 {
        return Err(anyhow!(
            "ownership proof expects 3 public inputs, got {}",
            pi.len()
        ));
    }
    let public = PublicInputs {
        owner: pi[0],
        nft_hash: pi[1],
        binding_hash: pi[2],
    };

    let proof_fields = sp
        .proof
        .iter()
        .map(|s| {
            hex::decode(s.strip_prefix("0x").unwrap_or(s)).context("decode proof field")
        })
        .collect::<Result<Vec<_>>>()?;
    let proof = pso_zk_backend::barretenberg::Proof {
        proof: proof_fields,
    };

    let backend = Barretenberg::default();
    let valid = ProofVerifier::<PsoV1, OwnershipProof>::verify(&backend, &public, &proof)
        .context("verify ownership proof")?;

    let rows = vec![
        kv("Proof Mode", &sp.mode),
        kv("Circuit Hash", &sp.circuit_hash),
        kv("Verification Result", if valid { "VALID" } else { "INVALID" }),
    ];
    println!("{}", build_table(&rows));

    if !valid {
        return Err(anyhow!("Proof verification returned INVALID"));
    }
    Ok(())
}

fn kv(field: &str, value: &str) -> KeyValueRow {
    KeyValueRow {
        field: field.to_string(),
        value: value.to_string(),
    }
}
