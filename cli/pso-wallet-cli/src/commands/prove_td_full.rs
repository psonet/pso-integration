//! `pso-wallet-cli prove-td-ownership` — Phase 2 of the redesigned
//! flow.
//!
//! Generates the post-mint TD ownership proof — a wallet-local
//! artifact used by L1-redemption tooling. Not consumed by L2.
//!
//! Inputs:
//!   - `--td-material`: the JSON `prepare-td-keypair`/`aggregate`
//!     emitted earlier (contains `td_sk`, `td_pk`, `td_nonce`,
//!     `td_derived_owner`).
//!   - `--tribute-draft-id`: 32-byte hex.
//!   - `--td-hash`: 32-byte LE Fr hex of the TD entity hash per
//!     §3.3.3, recomputed by the wallet from on-chain fields via
//!     `pso_protocol::nft::compute_tribute_draft_hash`.
//!
//! Output: `TdOwnershipProof` JSON. Currently the proof step errors
//! with `CircuitNotAvailable` — same circuit as the SU ownership
//! proof; see `docs/aggregation-redesign.md`.

use std::path::PathBuf;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use clap::Args as ClapArgs;
use eyre::Result;
use pso_l2_client::wallet::{prove_td_ownership, TdOwnershipMaterial};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON file produced by `aggregate` (TD material output).
    #[arg(long)]
    pub td_material: PathBuf,
    /// 32-byte hex of the on-chain TD id.
    #[arg(long)]
    pub tribute_draft_id: String,
    /// 32-byte LE Fr hex of the TD entity hash.
    #[arg(long)]
    pub td_hash: String,
    /// Output JSON path for the proof bundle.
    #[arg(long)]
    pub output: PathBuf,
}

pub fn run(_consent_key: &[u8; 32], args: Args) -> Result<()> {
    let material: TdOwnershipMaterial = crate::read_json(&args.td_material)?;
    let tdid = super::parse_uint256(&args.tribute_draft_id)?;
    let td_hash_bytes = strip_hex(&args.td_hash)?;
    if td_hash_bytes.len() != 32 {
        eyre::bail!("td_hash must be 32 bytes, got {}", td_hash_bytes.len());
    }
    let td_hash = Fr::from_le_bytes_mod_order(&td_hash_bytes);

    let proof = prove_td_ownership(&material, tdid, td_hash)?;
    crate::write_json(&args.output, &proof)?;
    println!(
        "{{\"tribute_draft_id\":\"{}\",\"td_derived_owner\":\"{}\"}}",
        proof.tribute_draft_id, proof.td_derived_owner_le_hex
    );
    Ok(())
}

fn strip_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}
