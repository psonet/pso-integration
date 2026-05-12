//! `pso-sra-cli mint-su` — mint a SpendingUnit on L2.

use clap::Args as ClapArgs;
use eyre::Result;
use pso_l2_client::L2Client;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// 32-byte hex SU id (`0x...`).
    #[arg(long)]
    pub su_id: String,
    /// Wallet-supplied `derivedOwner` Poseidon5 commitment (32 byte hex).
    #[arg(long)]
    pub derived_owner: String,
    /// ISO 4217 currency numeric code (e.g. 978 = EUR).
    #[arg(long)]
    pub currency: u16,
    /// Worldwide-day count (days since 2021-01-01).
    #[arg(long)]
    pub worldwide_day: u32,
    /// Settlement amount integer part.
    #[arg(long)]
    pub amount_base: u64,
    /// Settlement amount fractional part (atto, uint128).
    #[arg(long, default_value_t = 0)]
    pub amount_atto: u128,
    /// Comma-separated SR ids backing this SU (hex `0x...`).
    #[arg(long)]
    pub sr_ids: String,
    /// Comma-separated amendment-SR ids (hex `0x...`). Optional.
    #[arg(long, default_value = "")]
    pub amendment_sr_ids: String,
}

pub async fn run(client: &L2Client, args: Args) -> Result<()> {
    let mint_args = pso_l2_client::sra::MintSpendingUnitArgs {
        su_id: super::parse_uint256(&args.su_id)?,
        derived_owner: super::parse_b32(&args.derived_owner)?,
        settlement_currency: args.currency,
        worldwide_day: args.worldwide_day,
        settlement_amount_base: args.amount_base,
        settlement_amount_atto: args.amount_atto,
        sr_ids: super::parse_uint256_list(&args.sr_ids)?,
        amendment_sr_ids: super::parse_uint256_list(&args.amendment_sr_ids)?,
    };
    let tx_hash = pso_l2_client::sra::mint_spending_unit(client, mint_args).await?;
    println!("{{\"tx_hash\":\"{:?}\"}}", tx_hash);
    Ok(())
}
