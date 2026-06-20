//! `pso-attester-cli` — command-line frontend for Attester-side L2 operations.
//!
//! ```text
//! pso-attester-cli register-sr  --sr-id 0x...
//! pso-attester-cli register-ar  --ar-id 0x...
//! pso-attester-cli mint-su      --su-id 0x... --derived-owner 0x... --currency 978 \
//!                          --worldwide-day 20250923 --amount-base 100 --amount-atto 0 \
//!                          --sr-ids 0x..,0x.. --amendment-sr-ids
//! ```
//!
//! Every command requires `--rpc <URL>` and `--key <HEX>` (or
//! `PSO_L2_RPC` / `PSO_ATTESTER_KEY` env vars). SR/AR/SU submits go directly
//! through the `pso-chain-abi` interfaces on a thin local alloy RPC
//! handle; `mint-su` derives the SU id / owner / hash via the attester
//! FFI before submitting.

use clap::Parser;
use eyre::Result;

mod client;
mod commands;

use client::AttesterRpc;

#[derive(Parser, Debug)]
#[command(
    name = "pso-attester-cli",
    version,
    about = "PSO Attester-side L2 operations"
)]
struct Cli {
    /// L2 JSON-RPC URL. Falls back to `$PSO_L2_RPC`.
    #[arg(long, env = "PSO_L2_RPC")]
    rpc: String,

    /// L2 chain id (devnet `19280501`).
    #[arg(long, env = "PSO_L2_CHAIN_ID", default_value_t = 19_280_501)]
    chain_id: u64,

    /// 32-byte hex secret key (Attester signer). Falls back to `$PSO_ATTESTER_KEY`.
    #[arg(long, env = "PSO_ATTESTER_KEY")]
    key: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// Submit a spending record.
    RegisterSr(commands::register_sr::Args),
    /// Submit a spending-record amendment.
    RegisterAr(commands::register_ar::Args),
    /// Mint a SpendingUnit.
    MintSu(commands::mint_su::Args),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("PSO_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let key = parse_key_hex(&cli.key)?;
    let client = AttesterRpc::connect(&cli.rpc, cli.chain_id, &key)?;

    match cli.command {
        Command::RegisterSr(args) => commands::register_sr::run(&client, args).await,
        Command::RegisterAr(args) => commands::register_ar::run(&client, args).await,
        Command::MintSu(args) => commands::mint_su::run(&client, args).await,
    }
}

fn parse_key_hex(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        eyre::bail!("secret key must be 32 hex bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
