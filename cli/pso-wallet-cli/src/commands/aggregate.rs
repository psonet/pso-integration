//! `pso-wallet-cli aggregate` — fold N ownership records into one
//! aggregation proof + public-input bundle.

use std::path::PathBuf;

use clap::Args as ClapArgs;
use eyre::Result;
use pso_l2_client::artifacts::SuOwnershipRecord;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON files produced by `prepare-su`, one per SU being aggregated.
    #[arg(long, num_args = 1..)]
    pub records: Vec<PathBuf>,
    /// On-chain SU ids parallel to `--records` (comma-separated hex).
    #[arg(long)]
    pub su_ids: String,
    /// TributeDraft id the proof binds to (32-byte hex).
    #[arg(long)]
    pub tribute_draft_id: String,
    /// Output JSON path for the aggregation bundle.
    #[arg(long)]
    pub output: PathBuf,
}

pub fn run(key: &[u8; 32], chain_id: u64, args: Args) -> Result<()> {
    let records: Vec<SuOwnershipRecord> = args
        .records
        .iter()
        .map(crate::read_json::<SuOwnershipRecord>)
        .collect::<Result<_>>()?;
    let su_ids = super::parse_uint256_list(&args.su_ids)?;
    let tdid = super::parse_uint256(&args.tribute_draft_id)?;

    let bundle =
        pso_l2_client::wallet::aggregate_ownership(pso_l2_client::wallet::AggregateInputs {
            secret_key: key,
            records: &records,
            su_ids: &su_ids,
            tribute_draft_id: tdid,
            chain_id,
        })?;

    crate::write_json(&args.output, &bundle)?;
    println!(
        "{{\"tier_n\":{},\"label\":\"{}\",\"tribute_draft_id\":\"{}\"}}",
        bundle.tier.tier_n, bundle.tier.label, bundle.tribute_draft_id
    );
    Ok(())
}
