//! Serializable bridge types for the CLI.
//!
//! These types bridge the gap between in-memory domain types (which are not
//! serializable) and the JSON file-based workflow of the CLI. Three bridge
//! types are provided:
//!
//! - [`GeneratedOutput`]: wraps NFT JSON plus secret key and nonce for
//!   subsequent proof generation.
//! - [`SerializableProof`]: wraps proof bytes and public inputs in
//!   base58-encoded form for file storage.
//! - [`SerializableMerklePathElement`]: wraps a Merkle path element with
//!   base58-encoded node hash and string index.
//!
//! Conversion functions translate between domain types and these serializable
//! forms.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use pso_protocol::merkle::{MerklePathElement, MerklePathElementIndex};
use pso_zk_circuit_noir::NoirProof;

// -- Constants --

/// Expected byte length for Merkle path node hashes (BN254 field element).
const MERKLE_HASH_BYTE_LEN: usize = 32;

// -- Bridge types --

/// Output of `nft generate` -- saved to JSON.
///
/// Contains the NFT data plus the secret key and nonce required for
/// subsequent proof generation. The secret key is hex-encoded.
///
/// **WARNING**: This file contains a private key. Treat it as sensitive.
#[derive(Serialize, Deserialize)]
pub struct GeneratedOutput {
    /// Prominent warning that the file contains sensitive material.
    #[serde(rename = "WARNING")]
    pub warning: String,
    /// The NFT data (TributeDraft or SpendingUnit JSON).
    pub nft: serde_json::Value,
    /// NFT type discriminator ("tribute-draft" or "spending-unit").
    pub nft_type: String,
    /// Hex-encoded secp256k1 secret key (32 bytes).
    pub secret_key_hex: String,
    /// Hex-encoded nonce field element (32 bytes, little-endian).
    pub nonce_hex: String,
    /// Merkle path for testing (generated randomly).
    pub merkle_path: Vec<SerializableMerklePathElement>,
}

/// Serializable representation of a Merkle path element.
#[derive(Serialize, Deserialize)]
pub struct SerializableMerklePathElement {
    /// Base58-encoded node hash (32 bytes).
    pub node_hash: String,
    /// Position index: "skip", "left", or "right".
    pub index: String,
}

/// Output of `proof generate` -- saved to JSON.
///
/// Contains the proof and public inputs in base58 encoding,
/// plus metadata for human readability.
#[derive(Serialize, Deserialize)]
pub struct SerializableProof {
    /// Base58-encoded proof bytes.
    pub proof: String,
    /// Base58-encoded public input field elements.
    pub public_inputs: Vec<String>,
    /// Proof mode used ("full" or "ownership").
    pub mode: String,
    /// Circuit hash for traceability.
    pub circuit_hash: String,
    /// Circuit version.
    pub circuit_version: String,
}

// -- Conversion functions --

/// Convert domain `MerklePathElement` slice to serializable form.
///
/// Each element's `node_hash` is base58-encoded and the `index` is
/// mapped to a human-readable string ("skip", "left", or "right").
pub fn to_serializable_merkle_path(
    path: &[MerklePathElement],
) -> Vec<SerializableMerklePathElement> {
    path.iter()
        .map(|elem| {
            let index_str = match elem.index {
                MerklePathElementIndex::Skip => "skip",
                MerklePathElementIndex::Left => "left",
                MerklePathElementIndex::Right => "right",
            };
            SerializableMerklePathElement {
                node_hash: bs58::encode(&elem.node_hash).into_string(),
                index: index_str.to_string(),
            }
        })
        .collect()
}

/// Reconstruct domain `MerklePathElement` values from serialized form.
///
/// Validates that each `node_hash` is valid base58 encoding of exactly
/// 32 bytes, and that each `index` is one of "skip", "left", or "right".
/// Returns an error instead of panicking on invalid input.
pub fn from_serializable_merkle_path(
    path: &[SerializableMerklePathElement],
) -> Result<Vec<MerklePathElement>> {
    path.iter()
        .map(|elem| {
            let hash_bytes = bs58::decode(&elem.node_hash)
                .into_vec()
                .context("Invalid base58 in merkle path node_hash")?;
            if hash_bytes.len() != MERKLE_HASH_BYTE_LEN {
                return Err(anyhow!(
                    "Merkle path node_hash must be exactly {} bytes, got {}",
                    MERKLE_HASH_BYTE_LEN,
                    hash_bytes.len()
                ));
            }
            let node_hash: [u8; 32] = hash_bytes
                .as_slice()
                .try_into()
                .expect("length checked above");
            let index = match elem.index.as_str() {
                "skip" => MerklePathElementIndex::Skip,
                "left" => MerklePathElementIndex::Left,
                "right" => MerklePathElementIndex::Right,
                other => return Err(anyhow!("Unknown merkle path index: {}", other)),
            };
            Ok(MerklePathElement { node_hash, index })
        })
        .collect()
}

/// Convert `NoirProof` to serializable form using the `Proof` trait.
///
/// Uses the `Proof` trait methods which return base58-encoded strings,
/// plus circuit version metadata for traceability.
pub fn to_serializable_proof(
    proof: &NoirProof,
    mode: &str,
    version: &pso_zk_circuit_noir::ZKCircuitVersion,
) -> SerializableProof {
    use pso_zk_circuit_noir::Proof;
    SerializableProof {
        proof: proof.proof(),
        public_inputs: proof.public_inputs(),
        mode: mode.to_string(),
        circuit_hash: version.circuit_hash.clone(),
        circuit_version: version.circuit_version.clone(),
    }
}

/// Reconstruct `NoirProof` from serializable form.
///
/// Validates that `mode` is a recognized proof mode ("full" or "ownership")
/// and that all base58-encoded fields decode successfully.
pub fn from_serializable_proof(sp: &SerializableProof) -> Result<NoirProof> {
    // Validate mode before doing any work.
    match sp.mode.as_str() {
        "full" | "ownership" => {}
        other => return Err(anyhow!("Unknown proof mode: {}", other)),
    }

    let proof_bytes = bs58::decode(&sp.proof)
        .into_vec()
        .context("Invalid base58 in proof field")?;
    let public_inputs: Vec<Vec<u8>> = sp
        .public_inputs
        .iter()
        .map(|pi| {
            bs58::decode(pi)
                .into_vec()
                .context("Invalid base58 in public input")
        })
        .collect::<Result<_>>()?;
    Ok(NoirProof {
        proof: proof_bytes,
        public_inputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pso_protocol::merkle::{MerklePathElement, MerklePathElementIndex};

    // -- Fixtures --

    fn make_32_byte_array(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    fn make_merkle_element(fill: u8, index: MerklePathElementIndex) -> MerklePathElement {
        MerklePathElement {
            node_hash: make_32_byte_array(fill),
            index,
        }
    }

    fn make_minimal_generated_output() -> GeneratedOutput {
        GeneratedOutput {
            warning: "This file contains a secret key. Do not share.".to_string(),
            nft: serde_json::Value::Null,
            nft_type: "tribute-draft".to_string(),
            secret_key_hex: hex::encode([1u8; 32]),
            nonce_hex: hex::encode([2u8; 32]),
            merkle_path: vec![],
        }
    }

    fn make_minimal_serializable_proof() -> SerializableProof {
        SerializableProof {
            proof: bs58::encode([0xab, 0xcd]).into_string(),
            public_inputs: vec![bs58::encode([0xef]).into_string()],
            mode: "full".to_string(),
            circuit_hash: "abc123".to_string(),
            circuit_version: "0.0.1".to_string(),
        }
    }

    // -- Group 1: GeneratedOutput JSON Serialization --

    #[test]
    fn test_generated_output_json_roundtrip() {
        let original = GeneratedOutput {
            warning: "sensitive".to_string(),
            nft: serde_json::json!({ "id": "abc", "ownership": "xyz" }),
            nft_type: "tribute-draft".to_string(),
            secret_key_hex: hex::encode([7u8; 32]),
            nonce_hex: hex::encode([8u8; 32]),
            merkle_path: vec![SerializableMerklePathElement {
                node_hash: bs58::encode([1u8; 32]).into_string(),
                index: "left".to_string(),
            }],
        };

        let json = serde_json::to_string(&original).expect("serialize");
        let recovered: GeneratedOutput = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(recovered.warning, original.warning);
        assert_eq!(recovered.nft_type, original.nft_type);
        assert_eq!(recovered.secret_key_hex, original.secret_key_hex);
        assert_eq!(recovered.nonce_hex, original.nonce_hex);
        assert_eq!(recovered.merkle_path.len(), original.merkle_path.len());
        assert_eq!(
            recovered.merkle_path[0].index,
            original.merkle_path[0].index
        );
        assert_eq!(
            recovered.merkle_path[0].node_hash,
            original.merkle_path[0].node_hash
        );
    }

    #[test]
    fn test_generated_output_json_contains_warning_field() {
        let output = make_minimal_generated_output();
        let json = serde_json::to_string(&output).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let warning = value.get("WARNING").or_else(|| value.get("warning"));
        assert!(
            warning.is_some(),
            "JSON output must contain a WARNING or warning field; got: {}",
            json
        );
        let warning_str = warning.unwrap().as_str().unwrap_or("");
        assert!(!warning_str.is_empty(), "WARNING field must not be empty");
    }

    #[test]
    fn test_generated_output_nft_type_field_preserved() {
        let output = make_minimal_generated_output();
        let json = serde_json::to_string(&output).expect("serialize");
        let recovered: GeneratedOutput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered.nft_type, "tribute-draft");
    }

    // -- Group 2: SerializableMerklePathElement Serialization --

    #[test]
    fn test_merkle_path_element_serialization_roundtrip() {
        let original = SerializableMerklePathElement {
            node_hash: bs58::encode([42u8; 32]).into_string(),
            index: "left".to_string(),
        };

        let json = serde_json::to_string(&original).expect("serialize");
        let recovered: SerializableMerklePathElement =
            serde_json::from_str(&json).expect("deserialize");

        assert_eq!(recovered.node_hash, original.node_hash);
        assert_eq!(recovered.index, original.index);
    }

    #[test]
    fn test_to_serializable_merkle_path_all_variants() {
        let path = vec![
            make_merkle_element(1, MerklePathElementIndex::Skip),
            make_merkle_element(2, MerklePathElementIndex::Left),
            make_merkle_element(3, MerklePathElementIndex::Right),
        ];

        let result = to_serializable_merkle_path(&path);

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].index, "skip");
        assert_eq!(result[1].index, "left");
        assert_eq!(result[2].index, "right");
    }

    // -- Group 3: MerklePathElement Conversion Roundtrip --

    #[test]
    fn test_merkle_path_serialization_roundtrip() {
        let original = vec![
            make_merkle_element(0xAA, MerklePathElementIndex::Left),
            make_merkle_element(0xBB, MerklePathElementIndex::Right),
        ];

        let serialized = to_serializable_merkle_path(&original);
        let recovered = from_serializable_merkle_path(&serialized).expect("deserialize");

        assert_eq!(recovered.len(), original.len());
        for (orig, rec) in original.iter().zip(recovered.iter()) {
            assert_eq!(
                rec.node_hash.as_slice(),
                orig.node_hash.as_slice(),
                "node_hash mismatch"
            );
            assert_eq!(rec.index, orig.index, "index mismatch");
        }
    }

    #[test]
    fn test_merkle_path_skip_roundtrip() {
        let original = vec![make_merkle_element(0xFF, MerklePathElementIndex::Skip)];

        let serialized = to_serializable_merkle_path(&original);
        let recovered = from_serializable_merkle_path(&serialized).expect("deserialize");

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].index, MerklePathElementIndex::Skip);
    }

    // -- Group 4: Merkle Path Error Cases --

    #[test]
    fn test_merkle_path_unknown_index_returns_error() {
        let bad = vec![SerializableMerklePathElement {
            node_hash: bs58::encode([0u8; 32]).into_string(),
            index: "invalid".to_string(),
        }];

        let result = from_serializable_merkle_path(&bad);

        assert!(result.is_err(), "Expected Err for unknown index, got Ok");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.to_lowercase().contains("unknown") || err_msg.to_lowercase().contains("merkle"),
            "Error message should mention the unknown index: {}",
            err_msg
        );
    }

    #[test]
    fn test_merkle_path_wrong_byte_length_returns_error() {
        // base58-encode 17 bytes (not 32)
        let short_hash = bs58::encode([0xABu8; 17]).into_string();
        let bad = vec![SerializableMerklePathElement {
            node_hash: short_hash,
            index: "left".to_string(),
        }];

        let result = from_serializable_merkle_path(&bad);

        assert!(
            result.is_err(),
            "Expected Err for wrong byte length, got Ok — this would panic in GenericArray::clone_from_slice"
        );
    }

    #[test]
    fn test_merkle_path_invalid_base58_returns_error() {
        // '0', 'O', 'I', 'l' are not in the base58 alphabet
        let bad = vec![SerializableMerklePathElement {
            node_hash: "0OIl0OIl0OIl0OIl".to_string(),
            index: "left".to_string(),
        }];

        let result = from_serializable_merkle_path(&bad);

        assert!(result.is_err(), "Expected Err for invalid base58, got Ok");
    }

    // -- Group 5: SerializableProof JSON Serialization --

    #[test]
    fn test_serializable_proof_json_roundtrip() {
        let original = make_minimal_serializable_proof();

        let json = serde_json::to_string(&original).expect("serialize");
        let recovered: SerializableProof = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(recovered.proof, original.proof);
        assert_eq!(recovered.public_inputs, original.public_inputs);
        assert_eq!(recovered.mode, original.mode);
        assert_eq!(recovered.circuit_hash, original.circuit_hash);
        assert_eq!(recovered.circuit_version, original.circuit_version);
    }

    // -- Group 6: Security Properties --

    #[test]
    fn test_unknown_proof_mode_returns_error() {
        // from_serializable_proof is used by proof verify to reconstruct NoirProof.
        // Unknown mode values must return Err, not panic.
        let proof_bytes = bs58::encode([0xABu8; 4]).into_string();
        let bad = SerializableProof {
            proof: proof_bytes,
            public_inputs: vec![],
            mode: "quantum".to_string(),
            circuit_hash: "abc".to_string(),
            circuit_version: "0.0.1".to_string(),
        };

        let result = from_serializable_proof(&bad);

        assert!(
            result.is_err(),
            "Expected Err for unknown proof mode, got Ok"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.to_lowercase().contains("unknown") || err_msg.to_lowercase().contains("mode"),
            "Error message should mention the unknown mode: {}",
            err_msg
        );
    }

    // -- Edge cases --

    #[test]
    fn test_to_serializable_merkle_path_empty_input() {
        let result = to_serializable_merkle_path(&[]);
        assert!(result.is_empty(), "Empty input should produce empty output");
    }

    #[test]
    fn test_from_serializable_merkle_path_empty_input() {
        let result = from_serializable_merkle_path(&[]);
        assert!(result.is_ok(), "Empty input should succeed");
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_merkle_path_all_zero_hash_roundtrip() {
        // Ensure a 32-byte zero hash (valid BN254 field element) survives roundtrip.
        let original = vec![make_merkle_element(0x00, MerklePathElementIndex::Left)];
        let serialized = to_serializable_merkle_path(&original);
        let recovered =
            from_serializable_merkle_path(&serialized).expect("zero hash should roundtrip");
        assert_eq!(
            recovered[0].node_hash.as_slice(),
            original[0].node_hash.as_slice()
        );
    }
}
