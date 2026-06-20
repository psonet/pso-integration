//! `pso-attester-cli register-sr` — submit a spending record.

use clap::Args as ClapArgs;
use eyre::Result;

use crate::client::AttesterRpc;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// 32-byte hex SR id (`0x...`).
    #[arg(long)]
    pub sr_id: String,
}

pub async fn run(client: &AttesterRpc, args: Args) -> Result<()> {
    let sr_id = super::parse_uint256(&args.sr_id)?;
    let tx_hash = client.register_spending_record(sr_id).await?;
    println!("{{\"tx_hash\":\"{tx_hash:?}\"}}");
    Ok(())
}
