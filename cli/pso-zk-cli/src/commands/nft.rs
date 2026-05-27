//! Handler for the `nft generate` CLI command.
//!
//! Generates a random NFT (TributeDraft or SpendingUnit) with associated
//! owner keys, nonce, and Merkle path. Writes the result to a JSON file
//! and prints a summary table to stdout.

use std::path::Path;

use anyhow::{Context, Result};
use pso_integrations_shared::witness::fr_to_be32;
use rand::rngs::OsRng;

use pso_nft::{generate_test_merkle_path, Generated, GeneratedNFTData, SpendingUnit, TributeDraft};

use crate::display::{build_table, KeyValueRow};
use crate::types::{to_serializable_merkle_path, GeneratedOutput};
use crate::NftType;

/// Handle the `nft generate` command.
///
/// Generates a random NFT of the specified type, writes the result
/// (including secret key and nonce) to the output file as pretty-printed
/// JSON, and prints a summary table to stdout.
///
/// The output file contains sensitive material (secret key). File
/// permissions are set to 0600 on Unix systems, and a warning is
/// printed to stderr.
pub fn handle_nft_generate(nft_type: NftType, output: &Path) -> Result<()> {
    let mut rng = OsRng;

    let (generated_output, table_rows) = match nft_type {
        NftType::TributeDraft => {
            let data: GeneratedNFTData<TributeDraft> = TributeDraft::generate(&mut rng)?;
            let (output, rows) = build_generated_output(&data, "tribute-draft", &mut rng)?;
            (output, rows)
        }
        NftType::SpendingUnit => {
            let data: GeneratedNFTData<SpendingUnit> = SpendingUnit::generate(&mut rng)?;
            let (output, rows) = build_generated_output(&data, "spending-unit", &mut rng)?;
            (output, rows)
        }
    };

    // Write JSON to file.
    let json = serde_json::to_string_pretty(&generated_output)
        .context("Failed to serialize GeneratedOutput to JSON")?;
    std::fs::write(output, &json)
        .with_context(|| format!("Failed to write output file: {}", output.display()))?;

    // Set restrictive file permissions on Unix (0600 = owner read/write only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(output, permissions)
            .with_context(|| format!("Failed to set file permissions on {}", output.display()))?;
    }

    // Print warning to stderr about secret key material.
    eprintln!(
        "WARNING: Output file '{}' contains a secret key. Restrict access and do not commit to version control.",
        output.display()
    );

    // Print summary table to stdout.
    println!("{}", build_table(&table_rows));

    Ok(())
}

/// Build a `GeneratedOutput` and summary table rows from generated NFT data.
///
/// This is generic over the NFT type (TributeDraft or SpendingUnit) since
/// both implement `serde::Serialize`.
fn build_generated_output<T: serde::Serialize>(
    data: &GeneratedNFTData<T>,
    nft_type_str: &str,
    rng: &mut OsRng,
) -> Result<(GeneratedOutput, Vec<KeyValueRow>)> {
    // Serialize NFT to serde_json::Value.
    let nft_value =
        serde_json::to_value(&data.nft).context("Failed to serialize NFT to JSON value")?;

    // Hex-encode Grumpkin secret key bytes (32 bytes).
    let secret_key_hex = hex::encode(data.owner_keys.key.sk_bytes);

    // Hex-encode nonce (big-endian field element bytes — unified PSO
    // wire format).
    let nonce_bytes = fr_to_be32(&data.nonce);
    let nonce_hex = hex::encode(nonce_bytes);

    // Generate a test Merkle path.
    let merkle_path = generate_test_merkle_path(rng);
    let serializable_path = to_serializable_merkle_path(&merkle_path);

    let generated_output = GeneratedOutput {
        warning: "This file contains a secret key. Do not share or commit to version control."
            .to_string(),
        nft: nft_value.clone(),
        nft_type: nft_type_str.to_string(),
        secret_key_hex,
        nonce_hex,
        merkle_path: serializable_path,
    };

    // Build summary table rows (no secret material in table output).
    let mut rows = Vec::new();
    rows.push(KeyValueRow {
        field: "NFT Type".to_string(),
        value: nft_type_str.to_string(),
    });

    // Extract human-readable fields from the NFT JSON.
    if let Some(obj) = nft_value.as_object() {
        if let Some(id) = obj.get("id").and_then(|v| v.as_str()) {
            rows.push(KeyValueRow {
                field: "ID".to_string(),
                value: id.to_string(),
            });
        }
        if let Some(ownership) = obj.get("ownership").and_then(|v| v.as_str()) {
            rows.push(KeyValueRow {
                field: "Ownership".to_string(),
                value: ownership.to_string(),
            });
        }
        if let Some(currency) = obj.get("currency").and_then(|v| v.as_str()) {
            rows.push(KeyValueRow {
                field: "Currency".to_string(),
                value: currency.to_string(),
            });
        }
        if let Some(base) = obj.get("amount_base").and_then(|v| v.as_str()) {
            rows.push(KeyValueRow {
                field: "Amount Base".to_string(),
                value: base.to_string(),
            });
        }
    }

    rows.push(KeyValueRow {
        field: "Merkle Path Depth".to_string(),
        value: merkle_path.len().to_string(),
    });

    rows.push(KeyValueRow {
        field: "Output File".to_string(),
        value: "(see file path)".to_string(),
    });

    Ok((generated_output, rows))
}
