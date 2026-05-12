//! `pso-wallet-cli` — command-line frontend for wallet-side L2 operations.
//!
//! ```text
//! pso-wallet-cli prepare-su      --su-id 0x... --output ownership.json
//! pso-wallet-cli aggregate       --records r1.json r2.json --su-ids 0x..,0x.. \
//!                                --tribute-draft-id 0x... --output agg.json
//! pso-wallet-cli submit-td       --bundle agg.json
//! pso-wallet-cli prove-td-full   --td td.json --merkle-path path.json --output full.json
//! ```
//!
//! `--rpc` / `--chain-id` / `--key` apply to commands that hit L2.
//! Pure offline operations (`prepare-su`, `aggregate`, `prove-td-full`)
//! still need `--key`. JSON I/O uses the artifact types defined in
//! `pso_l2_client::artifacts`.

use std::path::PathBuf;

use clap::Parser;
use eyre::Result;

mod commands;

#[derive(Parser, Debug)]
#[command(
    name = "pso-wallet-cli",
    version,
    about = "PSO wallet-side L2 operations"
)]
struct Cli {
    /// L2 JSON-RPC URL (only required for `submit-td`). Defaults to
    /// `$PSO_L2_RPC`.
    #[arg(long, env = "PSO_L2_RPC", default_value = "")]
    rpc: String,

    /// L2 chain id (devnet `19280501`).
    #[arg(long, env = "PSO_L2_CHAIN_ID", default_value_t = 19_280_501)]
    chain_id: u64,

    /// 32-byte hex secret key (wallet signer). Falls back to `$PSO_WALLET_KEY`.
    #[arg(long, env = "PSO_WALLET_KEY")]
    key: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// Roll a nonce and compute `derivedOwner` for a single SU. Output
    /// is JSON the wallet stores and sends to the SRA.
    PrepareSu(commands::prepare_su::Args),
    /// Aggregate N ownership records into one proof bundle.
    Aggregate(commands::aggregate::Args),
    /// Broadcast `TributeDraft.submit(...)` using a previously-built bundle.
    SubmitTd(commands::submit_td::Args),
    /// Generate the ownership + Merkle inclusion full proof for a minted TD.
    ProveTdFull(commands::prove_td_full::Args),
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

    match cli.command {
        Command::PrepareSu(args) => commands::prepare_su::run(&key, args),
        Command::Aggregate(args) => commands::aggregate::run(&key, cli.chain_id, args),
        Command::SubmitTd(args) => {
            if cli.rpc.is_empty() {
                eyre::bail!("--rpc / PSO_L2_RPC required for `submit-td`");
            }
            let client =
                pso_l2_client::L2Client::connect_with_signer(&cli.rpc, cli.chain_id, &key)?;
            commands::submit_td::run(&client, args).await
        }
        Command::ProveTdFull(args) => commands::prove_td_full::run(&key, args),
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

/// Helper for subcommands that need to read a JSON artifact from a path.
pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Helper for subcommands that need to write a JSON artifact to a path.
pub(crate) fn write_json<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes)?;
    Ok(())
}
