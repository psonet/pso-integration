//! Integration tests for pso-zk-cli command handlers.
//!
//! These exercise the `nft generate` handler in-process. They do NOT run
//! proof generation/verification (too slow; covered upstream by the
//! pso-zk-circuits suite) and do not invoke the binary via
//! `std::process::Command`.

use std::path::PathBuf;

use pso_zk_cli::commands::nft::handle_nft_generate;
use pso_zk_cli::types::GeneratedOutput;
use pso_zk_cli::NftType;

fn write_to_temp_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let path = dir.path().join("output.json");
    (dir, path)
}

fn read_generated_output(path: &PathBuf) -> GeneratedOutput {
    let content = std::fs::read_to_string(path).expect("read output file");
    serde_json::from_str(&content).expect("deserialize GeneratedOutput")
}

#[test]
fn nft_generate_tribute_draft_writes_valid_json() {
    let (_dir, path) = write_to_temp_file();
    handle_nft_generate(NftType::TributeDraft, &path).expect("handle_nft_generate should succeed");
    assert!(path.exists(), "output file should exist after command");

    let output = read_generated_output(&path);
    assert_eq!(output.nft_type, "tribute-draft");
    assert!(output.tribute_draft.is_some(), "tribute_draft body present");
    assert!(output.spending_unit.is_none(), "no spending_unit body");
    assert!(
        !output.secret_key_hex.is_empty(),
        "secret_key_hex not empty"
    );
    assert!(!output.nonce_hex.is_empty(), "nonce_hex not empty");
}

#[test]
fn nft_generate_spending_unit_writes_valid_json() {
    let (_dir, path) = write_to_temp_file();
    handle_nft_generate(NftType::SpendingUnit, &path)
        .expect("handle_nft_generate should succeed for SpendingUnit");
    assert!(path.exists(), "output file should exist after command");

    let output = read_generated_output(&path);
    assert_eq!(output.nft_type, "spending-unit");
    assert!(output.spending_unit.is_some(), "spending_unit body present");
    assert!(!output.secret_key_hex.is_empty());
    assert!(!output.nonce_hex.is_empty());
}

#[test]
fn generated_output_secret_key_hex_is_valid_hex_32_bytes() {
    let (_dir, path) = write_to_temp_file();
    handle_nft_generate(NftType::TributeDraft, &path).expect("handle_nft_generate should succeed");
    let output = read_generated_output(&path);
    let bytes = hex::decode(&output.secret_key_hex).expect("secret_key_hex must be valid hex");
    assert_eq!(bytes.len(), 32, "Grumpkin secret key must be 32 bytes");
}

#[test]
fn generated_output_nonce_hex_is_valid_hex_32_bytes() {
    let (_dir, path) = write_to_temp_file();
    handle_nft_generate(NftType::TributeDraft, &path).expect("handle_nft_generate should succeed");
    let output = read_generated_output(&path);
    let bytes = hex::decode(&output.nonce_hex).expect("nonce_hex must be valid hex");
    assert_eq!(
        bytes.len(),
        32,
        "BN254 field element nonce must be 32 bytes"
    );
}

#[test]
fn generated_output_entity_reconstructs() {
    let (_dir, path) = write_to_temp_file();
    handle_nft_generate(NftType::SpendingUnit, &path).expect("handle_nft_generate should succeed");
    let output = read_generated_output(&path);

    let body = output.spending_unit.expect("spending_unit body present");
    assert_eq!(body.currency, 978);
    // The SU body must reconstruct into a typed pso-chain-abi entity.
    body.into_entity().expect("entity reconstructs");
}
