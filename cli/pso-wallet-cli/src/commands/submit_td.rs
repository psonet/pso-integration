//! `pso-wallet-cli submit-td` — broadcast `TributeDraft.submit(...)`
//! using a previously-built aggregation bundle.

use std::path::PathBuf;

use alloy_primitives::Bytes;
use clap::Args as ClapArgs;
use eyre::Result;

use crate::artifacts::AggregationBundleJson;
use crate::client::WalletRpc;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON aggregation bundle produced by `aggregate`.
    #[arg(long)]
    pub bundle: PathBuf,
    /// 32-byte hex TributeDraft id (`0x...`).
    #[arg(long)]
    pub td_id: String,
    /// 32-byte hex TD `derivedOwner` (`0x...`).
    #[arg(long)]
    pub derived_owner: String,
    /// Comma-separated SU ids the TD aggregates (hex `0x...`), in the
    /// order the proof commits to.
    #[arg(long)]
    pub su_ids: String,
}

pub async fn run(client: &WalletRpc, args: Args) -> Result<()> {
    let bundle: AggregationBundleJson = crate::read_json(&args.bundle)?;
    let td_id = super::parse_uint256(&args.td_id)?;
    let derived_owner = super::parse_b32(&args.derived_owner)?;
    let su_ids: Vec<_> = if args.su_ids.is_empty() {
        Vec::new()
    } else {
        args.su_ids
            .split(',')
            .map(|s| super::parse_uint256(s.trim()))
            .collect::<Result<_>>()?
    };
    let proof = hex::decode(bundle.proof.strip_prefix("0x").unwrap_or(&bundle.proof))?;

    let tx_hash = client
        .submit_tribute_draft(td_id, derived_owner, su_ids, Bytes::from(proof))
        .await?;
    println!("{{\"tx_hash\":\"{tx_hash:?}\",\"td_id\":\"{td_id:#x}\"}}");
    Ok(())
}
