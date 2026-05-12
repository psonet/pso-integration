//! `pso-sra-cli` — command-line frontend for SRA-side L2 operations.
//!
//! ```text
//! pso-sra-cli register-sr  --sr-id 0x... --keys "k1,k2" --values "0x..,0x.."
//! pso-sra-cli register-ar  --sr-id 0x... --keys "k1,k2" --values "0x..,0x.."
//! pso-sra-cli mint-su      --su-id 0x... --derived-owner 0x... --currency 978 \
//!                          --worldwide-day 1825 --amount-base 100 --amount-atto 0 \
//!                          --sr-ids 0x..,0x.. --amendment-sr-ids
//! ```
//!
//! Every command requires `--rpc <URL>` and `--key <HEX>` (or
//! `PSO_L2_RPC` / `PSO_SRA_KEY` env vars). All flows are thin wrappers
//! over `pso_l2_client::sra::*`.

use clap::Parser;
use eyre::Result;

mod commands;

#[derive(Parser, Debug)]
#[command(name = "pso-sra-cli", version, about = "PSO SRA-side L2 operations")]
struct Cli {
    /// L2 JSON-RPC URL. Falls back to `$PSO_L2_RPC`.
    #[arg(long, env = "PSO_L2_RPC")]
    rpc: String,

    /// L2 chain id (devnet `19280501`).
    #[arg(long, env = "PSO_L2_CHAIN_ID", default_value_t = 19_280_501)]
    chain_id: u64,

    /// 32-byte hex secret key (SRA signer). Falls back to `$PSO_SRA_KEY`.
    #[arg(long, env = "PSO_SRA_KEY")]
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
    let client = pso_l2_client::L2Client::connect_with_signer(&cli.rpc, cli.chain_id, &key)
        .map_err(|e| eyre::eyre!("connect: {e}"))?;

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
