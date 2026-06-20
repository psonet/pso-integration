//! `pso-wallet-cli` — command-line frontend for wallet-side L2 operations.
//!
//! ```text
//! pso-wallet-cli prepare-su      --report report.json --binding 0x... -o witness.json
//! pso-wallet-cli aggregate       --witnesses w1.json w2.json --binding 0x... -o agg.json
//! pso-wallet-cli submit-td       --bundle agg.json --td-id 0x... --derived-owner 0x...
//! pso-wallet-cli prove-td-full   --td td.json --output full.json
//! ```
//!
//! `--rpc` / `--chain-id` / `--key` apply to commands that hit L2.
//! Offline operations (`prepare-su`, `aggregate`, `prove-td-full`) still
//! need `--key` (the wallet seed). The wallet flows are driven through
//! the mobile FFI (`Consent::witness`, `Wallet::prove_ownership`); JSON
//! I/O uses the artifact types in [`artifacts`].

use std::path::PathBuf;

use clap::Parser;
use eyre::Result;

mod artifacts;
mod client;
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

    /// Wallet seed: >= 32 bytes of entropy as hex. Falls back to
    /// `$PSO_WALLET_KEY`. Used to derive the consent + signing
    /// randomness inside the mobile FFI.
    #[arg(long, env = "PSO_WALLET_KEY")]
    key: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// Turn an Attester-delivered issuance report into an ownership witness
    /// (`Consent::witness`) bound to a submission binding.
    PrepareSu(commands::prepare_su::Args),
    /// Aggregate N ownership witnesses into one proof bundle
    /// (`Wallet::prove_ownership`).
    Aggregate(commands::aggregate::Args),
    /// Broadcast `TributeDraft.submit(...)` using a previously-built bundle.
    SubmitTd(commands::submit_td::Args),
    /// Generate the post-mint TD ownership proof (not yet available).
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
    let seed = parse_seed_hex(&cli.key)?;

    match cli.command {
        Command::PrepareSu(args) => commands::prepare_su::run(&seed, args),
        Command::Aggregate(args) => commands::aggregate::run(&seed, args),
        Command::SubmitTd(args) => {
            if cli.rpc.is_empty() {
                eyre::bail!("--rpc / PSO_L2_RPC required for `submit-td`");
            }
            let client = client::WalletRpc::connect(&cli.rpc, cli.chain_id, &seed_to_key(&seed)?)?;
            commands::submit_td::run(&client, args).await
        }
        Command::ProveTdFull(args) => commands::prove_td_full::run(&seed, args),
    }
}

/// Parse the wallet seed: hex with an optional `0x` prefix, >= 32 bytes.
fn parse_seed_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() < 32 {
        eyre::bail!("wallet seed must be >= 32 bytes of entropy, got {}", bytes.len());
    }
    Ok(bytes)
}

/// The submitter's 32-byte secp256k1 signing key. For the reference CLI
/// the wallet seed's first 32 bytes double as the EVM signer key.
fn seed_to_key(seed: &[u8]) -> Result<[u8; 32]> {
    seed.get(..32)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| eyre::eyre!("seed too short for a 32-byte signing key"))
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
