//! `pso-sra-cli register-ar` — submit a spending-record amendment.

use clap::Args as ClapArgs;
use eyre::Result;
use pso_l2_client::L2Client;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// 32-byte hex AR id (`0x...`) — the amendment-record id.
    #[arg(long)]
    pub ar_id: String,
}

pub async fn run(client: &L2Client, args: Args) -> Result<()> {
    let ar_id = super::parse_uint256(&args.ar_id)?;

    let tx_hash = pso_l2_client::sra::register_amendment_record(client, ar_id).await?;
    println!("{{\"tx_hash\":\"{:?}\"}}", tx_hash);
    Ok(())
}
