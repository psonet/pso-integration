//! `pso-wallet-cli submit-td` — broadcast `TributeDraft.submit(...)`
//! using a previously-built aggregation bundle.

use std::path::PathBuf;

use clap::Args as ClapArgs;
use eyre::Result;
use pso_l2_client::artifacts::AggregationProofBundle;
use pso_l2_client::L2Client;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON file produced by `aggregate`.
    #[arg(long)]
    pub bundle: PathBuf,
}

pub async fn run(client: &L2Client, args: Args) -> Result<()> {
    let bundle: AggregationProofBundle = crate::read_json(&args.bundle)?;
    let tx_hash = pso_l2_client::wallet::submit_tribute_draft(client, &bundle).await?;
    println!(
        "{{\"tx_hash\":\"{:?}\",\"tribute_draft_id\":\"{}\"}}",
        tx_hash, bundle.tribute_draft_id
    );
    Ok(())
}
