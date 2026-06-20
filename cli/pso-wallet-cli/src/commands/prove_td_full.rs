//! `pso-wallet-cli prove-td-full` — Phase 2 of the redesigned flow.
//!
//! Would generate the post-mint TD ownership proof — a wallet-local
//! artifact for L1-redemption tooling, not consumed by L2. The
//! dedicated post-mint TD circuit is not yet exposed by the new
//! `pso-zk-canonical` surface, so this command returns a clear
//! "not yet available" error (as it did under the previous stack, where
//! it surfaced `CircuitNotAvailable`).

use std::path::PathBuf;

use clap::Args as ClapArgs;
use eyre::Result;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON file describing the minted TD (unused until the circuit lands).
    #[arg(long)]
    pub td: PathBuf,
    /// Output JSON path for the proof bundle (unused until the circuit lands).
    #[arg(long, short)]
    pub output: PathBuf,
}

pub fn run(_seed: &[u8], args: Args) -> Result<()> {
    let _ = args;
    eyre::bail!(
        "prove-td-full is not yet available: the post-mint TD ownership circuit \
         is not exposed by the current pso-zk-canonical surface. See \
         docs/aggregation-redesign.md."
    )
}
