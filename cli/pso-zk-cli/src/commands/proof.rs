//! Handlers for the `proof generate` and `proof verify` CLI commands.
//!
//! `proof generate` reads an NFT JSON file (from `nft generate`),
//! reconstructs the domain types, generates a ZK witness, loads the
//! circuit, and produces a proof saved to a JSON file.
//!
//! `proof verify` reads a proof JSON file (from `proof generate`),
//! loads the circuit, and verifies the proof.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use ark_bn254::Fr;
use ark_ff::PrimeField;

use pso_integrations_shared::witness::{
    build_full_proof_witness, build_ownership_witness, derive_grumpkin_public_key,
    FullProofWitnessCtx, GrumpkinKey, OwnershipWitnessCtx,
};
use pso_nft::{SpendingUnit, TributeDraft};
use pso_protocol::witness::HashableNFT;
use pso_zk_circuit_noir::{
    circuit_loader, NoirCircuitConfig, NoirFullProofCircuit, NoirOwnershipCircuit, NoirProof,
    ZKCircuit, ZKMode,
};

use crate::display::{build_table, KeyValueRow};
use crate::types::{
    from_serializable_merkle_path, from_serializable_proof, to_serializable_proof, GeneratedOutput,
    SerializableProof,
};
use crate::ProofMode;

// -- Constants --

/// Circuit version string matching the existing test suite.
const CIRCUIT_VERSION: &str = "0.0.1";

/// Handle the `proof generate` command.
///
/// Reads the NFT JSON file, reconstructs the secret key and nonce,
/// generates a ZK witness, loads the circuit, produces a proof, and
/// writes the serialized proof to the output file.
pub fn handle_proof_generate(
    nft_path: &Path,
    circuit_path: &Path,
    mode: ProofMode,
    output: &Path,
) -> Result<()> {
    // 1. Read and parse the GeneratedOutput from the NFT file.
    let nft_content = std::fs::read_to_string(nft_path)
        .with_context(|| format!("Failed to read NFT file: {}", nft_path.display()))?;
    let generated_output: GeneratedOutput = serde_json::from_str(&nft_content)
        .context("Failed to parse NFT file as GeneratedOutput")?;

    // 2. Reconstruct the Grumpkin secret key from hex (32 bytes).
    let secret_key_bytes = hex::decode(&generated_output.secret_key_hex)
        .context("Failed to decode secret_key_hex as hex")?;
    let sk_arr: [u8; 32] = secret_key_bytes
        .try_into()
        .map_err(|_| anyhow!("secret_key_hex must decode to exactly 32 bytes"))?;
    let grumpkin_key = derive_grumpkin_public_key(&sk_arr)
        .context("Failed to derive Grumpkin public key from secret key bytes")?;

    // 3. Reconstruct the nonce from hex with field validation.
    let nonce_bytes =
        hex::decode(&generated_output.nonce_hex).context("Failed to decode nonce_hex as hex")?;
    let nonce_arr: [u8; 32] = nonce_bytes
        .try_into()
        .map_err(|_| anyhow!("nonce_hex must decode to exactly 32 bytes"))?;
    let nonce: Fr = Fr::from_be_bytes_mod_order(&nonce_arr);

    // 4. Reconstruct the Merkle path from the serialized form.
    let merkle_path = from_serializable_merkle_path(&generated_output.merkle_path)
        .context("Failed to reconstruct Merkle path")?;

    // 5. Load the circuit bytecode.
    let circuit_bytecode = circuit_loader::load_circuit(circuit_path)
        .with_context(|| format!("Failed to load circuit: {}", circuit_path.display()))?;

    // 6. Dispatch based on proof mode and NFT type.
    let mode_str = match mode {
        ProofMode::Full => "full",
        ProofMode::Ownership => "ownership",
    };

    let serializable_proof = match mode {
        ProofMode::Full => generate_full_proof(
            &generated_output,
            &grumpkin_key,
            nonce,
            &merkle_path,
            circuit_bytecode,
        )?,
        ProofMode::Ownership => {
            generate_ownership_proof(&generated_output, &grumpkin_key, nonce, circuit_bytecode)?
        }
    };

    // 7. Write the proof to the output file.
    let json = serde_json::to_string_pretty(&serializable_proof)
        .context("Failed to serialize proof to JSON")?;
    std::fs::write(output, &json)
        .with_context(|| format!("Failed to write proof file: {}", output.display()))?;

    // 8. Print proof summary table.
    let rows = vec![
        KeyValueRow {
            field: "Proof Mode".to_string(),
            value: mode_str.to_string(),
        },
        KeyValueRow {
            field: "Circuit Hash".to_string(),
            value: serializable_proof.circuit_hash.clone(),
        },
        KeyValueRow {
            field: "Circuit Version".to_string(),
            value: serializable_proof.circuit_version.clone(),
        },
        KeyValueRow {
            field: "Public Inputs".to_string(),
            value: serializable_proof.public_inputs.len().to_string(),
        },
        KeyValueRow {
            field: "Output File".to_string(),
            value: output.display().to_string(),
        },
    ];
    println!("{}", build_table(&rows));

    Ok(())
}

/// Handle the `proof verify` command.
///
/// Reads the proof JSON file, reconstructs the `NoirProof`, loads the
/// circuit, and verifies the proof. Prints the verification result as
/// a table to stdout.
pub fn handle_proof_verify(proof_path: &Path, circuit_path: &Path) -> Result<()> {
    // 1. Read and parse the SerializableProof.
    let proof_content = std::fs::read_to_string(proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;
    let serializable_proof: SerializableProof = serde_json::from_str(&proof_content)
        .context("Failed to parse proof file as SerializableProof")?;

    // 2. Reconstruct NoirProof (also validates mode).
    let noir_proof = from_serializable_proof(&serializable_proof)
        .context("Failed to reconstruct NoirProof from serialized form")?;

    // 3. Load the circuit bytecode.
    let circuit_bytecode = circuit_loader::load_circuit(circuit_path)
        .with_context(|| format!("Failed to load circuit: {}", circuit_path.display()))?;

    // 4. Verify based on proof mode.
    let valid = match serializable_proof.mode.as_str() {
        "full" => {
            let config = NoirCircuitConfig {
                circuit: circuit_bytecode,
                version: CIRCUIT_VERSION,
                low_memory: false,
                scheme: ZKMode::UltraHonkKeccak,
            };
            let circuit = NoirFullProofCircuit::setup(config)
                .context("Failed to setup full proof circuit")?;
            circuit
                .verify(noir_proof)
                .context("Full proof verification failed")?
        }
        "ownership" => {
            let config = NoirCircuitConfig {
                circuit: circuit_bytecode,
                version: CIRCUIT_VERSION,
                low_memory: false,
                scheme: ZKMode::UltraHonkKeccak,
            };
            let circuit =
                NoirOwnershipCircuit::setup(config).context("Failed to setup ownership circuit")?;
            circuit
                .verify(noir_proof)
                .context("Ownership proof verification failed")?
        }
        other => return Err(anyhow!("Unknown proof mode: {}", other)),
    };

    // 5. Print verification result table.
    let result_str = if valid { "VALID" } else { "INVALID" };
    let rows = vec![
        KeyValueRow {
            field: "Proof Mode".to_string(),
            value: serializable_proof.mode.clone(),
        },
        KeyValueRow {
            field: "Circuit Hash".to_string(),
            value: serializable_proof.circuit_hash.clone(),
        },
        KeyValueRow {
            field: "Verification Result".to_string(),
            value: result_str.to_string(),
        },
    ];
    println!("{}", build_table(&rows));

    if !valid {
        return Err(anyhow!("Proof verification returned INVALID"));
    }

    Ok(())
}

// -- Internal helpers --

/// Generate a full proof (ownership + Merkle inclusion) for the given NFT data.
fn generate_full_proof(
    generated_output: &GeneratedOutput,
    key: &GrumpkinKey,
    nonce: Fr,
    merkle_path: &[pso_protocol::merkle::MerklePathElement],
    circuit_bytecode: pso_zk_circuit_noir::CircuitBytecode,
) -> Result<SerializableProof> {
    // Deserialize the NFT based on nft_type.
    let witness = match generated_output.nft_type.as_str() {
        "tribute-draft" => {
            let nft: TributeDraft = serde_json::from_value(generated_output.nft.clone())
                .context("Failed to deserialize NFT as TributeDraft")?;
            let ctx = FullProofWitnessCtx {
                key,
                nonce,
                merkle_path,
            };
            build_full_proof_witness(&nft, ctx)
                .context("Failed to generate full proof witness for TributeDraft")?
        }
        "spending-unit" => {
            let nft: SpendingUnit = serde_json::from_value(generated_output.nft.clone())
                .context("Failed to deserialize NFT as SpendingUnit")?;
            let ctx = FullProofWitnessCtx {
                key,
                nonce,
                merkle_path,
            };
            build_full_proof_witness(&nft, ctx)
                .context("Failed to generate full proof witness for SpendingUnit")?
        }
        other => return Err(anyhow!("Unknown NFT type: {}", other)),
    };

    let config = NoirCircuitConfig {
        circuit: circuit_bytecode,
        version: CIRCUIT_VERSION,
        low_memory: false,
        scheme: ZKMode::UltraHonkKeccak,
    };

    let circuit =
        NoirFullProofCircuit::setup(config).context("Failed to setup full proof circuit")?;
    let version = circuit.version();
    let proof: NoirProof = circuit
        .prove(witness)
        .context("Failed to generate full proof")?;

    Ok(to_serializable_proof(&proof, "full", &version))
}

/// Generate an ownership-only proof for the given NFT data.
fn generate_ownership_proof(
    generated_output: &GeneratedOutput,
    key: &GrumpkinKey,
    nonce: Fr,
    circuit_bytecode: pso_zk_circuit_noir::CircuitBytecode,
) -> Result<SerializableProof> {
    // Deserialize the NFT based on nft_type.
    let witness = match generated_output.nft_type.as_str() {
        "tribute-draft" => {
            let nft: TributeDraft = serde_json::from_value(generated_output.nft.clone())
                .context("Failed to deserialize NFT as TributeDraft")?;
            let nft_hash = HashableNFT::hash(&nft).context("td hash")?;
            let ctx = OwnershipWitnessCtx {
                key,
                nonce,
                nft_hash,
            };
            build_ownership_witness(&nft, ctx)
                .context("Failed to generate ownership witness for TributeDraft")?
        }
        "spending-unit" => {
            let nft: SpendingUnit = serde_json::from_value(generated_output.nft.clone())
                .context("Failed to deserialize NFT as SpendingUnit")?;
            let nft_hash = HashableNFT::hash(&nft).context("su hash")?;
            let ctx = OwnershipWitnessCtx {
                key,
                nonce,
                nft_hash,
            };
            build_ownership_witness(&nft, ctx)
                .context("Failed to generate ownership witness for SpendingUnit")?
        }
        other => return Err(anyhow!("Unknown NFT type: {}", other)),
    };

    let config = NoirCircuitConfig {
        circuit: circuit_bytecode,
        version: CIRCUIT_VERSION,
        low_memory: false,
        scheme: ZKMode::UltraHonkKeccak,
    };

    let circuit =
        NoirOwnershipCircuit::setup(config).context("Failed to setup ownership circuit")?;
    let version = circuit.version();
    let proof: NoirProof = circuit
        .prove(witness)
        .context("Failed to generate ownership proof")?;

    Ok(to_serializable_proof(&proof, "ownership", &version))
}
