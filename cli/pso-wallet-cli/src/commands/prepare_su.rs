//! `pso-wallet-cli prepare-su` — roll a (nonce, derivedOwner) pair
//! the wallet will hand to the SRA so the SRA can mint a SpendingUnit
//! the wallet later proves ownership of.

use std::path::PathBuf;

use clap::Args as ClapArgs;
use eyre::Result;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// 32-byte hex SU id the SRA will mint under (`0x...`).
    #[arg(long)]
    pub su_id: String,
    /// Output JSON path. Wallet stores this; sends only
    /// `.derived_owner` to the SRA.
    #[arg(long)]
    pub output: PathBuf,
}

pub fn run(key: &[u8; 32], args: Args) -> Result<()> {
    let su_id = super::parse_uint256(&args.su_id)?;
    let record = pso_l2_client::wallet::prepare_su_ownership(key, su_id)?;
    crate::write_json(&args.output, &record)?;
    println!(
        "{{\"su_id\":\"{}\",\"derived_owner\":\"{}\"}}",
        record.su_id, record.derived_owner
    );
    Ok(())
}
