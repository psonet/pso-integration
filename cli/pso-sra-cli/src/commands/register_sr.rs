//! `pso-sra-cli register-sr` — submit a spending record.

use clap::Args as ClapArgs;
use eyre::Result;
use pso_l2_client::L2Client;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// 32-byte hex SR id (`0x...`).
    #[arg(long)]
    pub sr_id: String,
    /// Comma-separated record keys.
    #[arg(long)]
    pub keys: String,
    /// Comma-separated `bytes32` hex values, parallel to `--keys`.
    #[arg(long)]
    pub values: String,
}

pub async fn run(client: &L2Client, args: Args) -> Result<()> {
    let sr_id = super::parse_uint256(&args.sr_id)?;
    let keys = super::parse_string_list(&args.keys);
    let values = super::parse_b32_list(&args.values)?;

    let tx_hash = pso_l2_client::sra::register_spending_record(client, sr_id, keys, values).await?;
    println!("{{\"tx_hash\":\"{:?}\"}}", tx_hash);
    Ok(())
}
