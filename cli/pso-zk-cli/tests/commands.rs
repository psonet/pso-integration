//! Integration tests for pso-zk-cli command handlers.
//!
//! These tests exercise the command handler functions directly in-process.
//! They do NOT invoke the binary via `std::process::Command` and do NOT
//! run full proof generation or verification (too slow; covered upstream).

use std::path::PathBuf;

use pso_zk_cli::commands::nft::handle_nft_generate;
use pso_zk_cli::types::{
    from_serializable_merkle_path, to_serializable_merkle_path, GeneratedOutput,
};
use pso_zk_cli::NftType;

use pso_nft::TributeDraft;

// -- Helpers --

fn write_to_temp_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let path = dir.path().join("output.json");
    (dir, path)
}

fn read_generated_output(path: &PathBuf) -> GeneratedOutput {
    let content = std::fs::read_to_string(path).expect("read output file");
    serde_json::from_str(&content).expect("deserialize GeneratedOutput")
}

// -- Tests --

#[test]
fn test_nft_generate_tribute_draft_writes_valid_json() {
    let (_dir, path) = write_to_temp_file();

    handle_nft_generate(NftType::TributeDraft, &path).expect("handle_nft_generate should succeed");

    assert!(path.exists(), "output file should exist after command");

    let output = read_generated_output(&path);
    assert_eq!(output.nft_type, "tribute-draft");
    assert!(
        !output.secret_key_hex.is_empty(),
        "secret_key_hex must not be empty"
    );
    assert!(!output.nonce_hex.is_empty(), "nonce_hex must not be empty");
}

#[test]
fn test_nft_generate_spending_unit_writes_valid_json() {
    let (_dir, path) = write_to_temp_file();

    handle_nft_generate(NftType::SpendingUnit, &path)
        .expect("handle_nft_generate should succeed for SpendingUnit");

    assert!(path.exists(), "output file should exist after command");

    let output = read_generated_output(&path);
    assert_eq!(output.nft_type, "spending-unit");
    assert!(!output.secret_key_hex.is_empty());
    assert!(!output.nonce_hex.is_empty());
}

#[test]
fn test_generated_output_nft_field_deserializes_as_tribute_draft() {
    let (_dir, path) = write_to_temp_file();

    handle_nft_generate(NftType::TributeDraft, &path).expect("handle_nft_generate should succeed");

    let output = read_generated_output(&path);

    // The `nft` field is a serde_json::Value. We must be able to
    // deserialize it as a TributeDraft.
    let tribute: TributeDraft =
        serde_json::from_value(output.nft).expect("nft field must deserialize as TributeDraft");

    // Basic sanity: the currency should be a known currency string.
    // The TributeDraft fields id and owner are BN254 field elements so just
    // check they round-trip through the JSON format (non-empty base58 strings).
    let json_value = serde_json::to_value(&tribute).expect("re-serialize");
    let id_str = json_value["id"].as_str().expect("id should be a string");
    assert!(
        !id_str.is_empty(),
        "TributeDraft id must be non-empty base58"
    );

    let ownership_str = json_value["ownership"]
        .as_str()
        .expect("ownership should be a string");
    assert!(
        !ownership_str.is_empty(),
        "TributeDraft ownership must be non-empty base58"
    );
}

#[test]
fn test_generated_output_merkle_path_roundtrip() {
    let (_dir, path) = write_to_temp_file();

    handle_nft_generate(NftType::TributeDraft, &path).expect("handle_nft_generate should succeed");

    let output = read_generated_output(&path);

    // The merkle_path field in GeneratedOutput is Vec<SerializableMerklePathElement>.
    // Round-trip it through from_serializable_merkle_path and back.
    let domain_path = from_serializable_merkle_path(&output.merkle_path)
        .expect("merkle path in output should deserialize without error");

    let re_serialized = to_serializable_merkle_path(&domain_path);

    assert_eq!(re_serialized.len(), output.merkle_path.len());
    for (original, recovered) in output.merkle_path.iter().zip(re_serialized.iter()) {
        assert_eq!(
            original.node_hash, recovered.node_hash,
            "node_hash changed in roundtrip"
        );
        assert_eq!(
            original.index, recovered.index,
            "index changed in roundtrip"
        );
    }
}

#[test]
fn test_generated_output_secret_key_hex_is_valid_hex_32_bytes() {
    let (_dir, path) = write_to_temp_file();

    handle_nft_generate(NftType::TributeDraft, &path).expect("handle_nft_generate should succeed");

    let output = read_generated_output(&path);

    let bytes = hex::decode(&output.secret_key_hex).expect("secret_key_hex must be valid hex");
    assert_eq!(
        bytes.len(),
        32,
        "secp256k1 secret key must be exactly 32 bytes"
    );
}

#[test]
fn test_generated_output_nonce_hex_is_valid_hex_32_bytes() {
    let (_dir, path) = write_to_temp_file();

    handle_nft_generate(NftType::TributeDraft, &path).expect("handle_nft_generate should succeed");

    let output = read_generated_output(&path);

    let bytes = hex::decode(&output.nonce_hex).expect("nonce_hex must be valid hex");
    assert_eq!(
        bytes.len(),
        32,
        "BN254 field element nonce must be exactly 32 bytes"
    );
}

#[test]
fn test_generated_output_merkle_path_has_at_most_depth_elements() {
    use pso_protocol::merkle::SPARSE_MERKLE_PATH_DEPTH;

    let (_dir, path) = write_to_temp_file();

    handle_nft_generate(NftType::TributeDraft, &path).expect("handle_nft_generate should succeed");

    let output = read_generated_output(&path);

    // generate_test_merkle_path uses range 4..8 (exclusive upper bound),
    // so length is between 4 and 7 inclusive. Must not exceed SPARSE_MERKLE_PATH_DEPTH.
    assert!(
        output.merkle_path.len() >= 4,
        "Merkle path should have at least 4 elements (generated minimum)"
    );
    assert!(
        output.merkle_path.len() <= SPARSE_MERKLE_PATH_DEPTH,
        "Merkle path length {} exceeds SPARSE_MERKLE_PATH_DEPTH {}",
        output.merkle_path.len(),
        SPARSE_MERKLE_PATH_DEPTH
    );
}
