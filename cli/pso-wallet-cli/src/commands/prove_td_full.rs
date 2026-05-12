//! `pso-wallet-cli prove-td-full` — generate the ownership +
//! Merkle-inclusion full proof for a minted TributeDraft.

use std::path::PathBuf;

use clap::Args as ClapArgs;
use eyre::Result;
use pso_l2_client::wallet::{FullProofTributeDraft, MerklePathElementInput};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON file describing the TD (id, derivedOwner, nonce, fields, su_ids).
    /// Schema matches `pso_l2_client::wallet::FullProofTributeDraft`.
    #[arg(long)]
    pub td: PathBuf,
    /// JSON file containing a `Vec<MerklePathElementInput>`.
    #[arg(long)]
    pub merkle_path: PathBuf,
    /// Output JSON path for the proof bundle.
    #[arg(long)]
    pub output: PathBuf,
}

pub fn run(key: &[u8; 32], args: Args) -> Result<()> {
    let td: FullProofTributeDraft = crate::read_json(&args.td)?;
    let path: Vec<MerklePathElementInput> = crate::read_json(&args.merkle_path)?;
    let bundle = pso_l2_client::wallet::generate_full_proof(key, &td, &path)?;
    crate::write_json(&args.output, &bundle)?;
    println!(
        "{{\"tribute_draft_id\":\"{}\",\"public_inputs\":{}}}",
        bundle.tribute_draft_id,
        bundle.public_inputs.len()
    );
    Ok(())
}
