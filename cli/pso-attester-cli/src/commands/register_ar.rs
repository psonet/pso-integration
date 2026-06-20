//! `pso-attester-cli register-ar` — submit a spending-record amendment.

use clap::Args as ClapArgs;
use eyre::Result;

use crate::client::AttesterRpc;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// 32-byte hex AR id (`0x...`) — the amendment-record id.
    #[arg(long)]
    pub ar_id: String,
}

pub async fn run(client: &AttesterRpc, args: Args) -> Result<()> {
    let ar_id = super::parse_uint256(&args.ar_id)?;
    let tx_hash = client.register_amendment_record(ar_id).await?;
    println!("{{\"tx_hash\":\"{tx_hash:?}\"}}");
    Ok(())
}
