//! `pso-wallet-cli aggregate` — build a flat-aggregation proof from N
//! per-SU ownership witnesses (`Wallet::prove_ownership`).
//!
//! Loads each witness produced by `prepare-su`, picks the smallest
//! canonical tier `>= n`, and runs a single aggregation prove pass
//! against the chosen tier's VK. The per-SU constraint set is duplicated
//! inline — no per-SU intermediate proofs.

use std::path::PathBuf;

use clap::Args as ClapArgs;
use eyre::Result;

use crate::artifacts::{AggregationBundleJson, OwnershipWitnessJson};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON witnesses produced by `prepare-su` — one per SU. Every
    /// witness must commit to the same `--binding`.
    #[arg(long, num_args = 1..)]
    pub witnesses: Vec<PathBuf>,
    /// The shared submission binding (32-byte hex). Must match the one
    /// the witnesses signed over.
    #[arg(long)]
    pub binding: String,
    /// Output JSON path for the aggregation bundle.
    #[arg(long, short)]
    pub output: PathBuf,
}

pub fn run(seed: &[u8], args: Args) -> Result<()> {
    let binding = strip_hex(&args.binding)?;
    let witnesses: Vec<pso_mobile_integration::NftOwnershipWitness> = args
        .witnesses
        .iter()
        .map(|p| {
            let json: OwnershipWitnessJson = crate::read_json(p)?;
            json.into_ffi()
        })
        .collect::<Result<_>>()?;

    let wallet = pso_mobile_integration::Wallet::new();
    let result = wallet
        .prove_ownership(seed.to_vec(), binding, witnesses)
        .map_err(|e| eyre::eyre!("prove_ownership: {e:?}"))?;

    let bundle = AggregationBundleJson::from_ffi(&result);
    crate::write_json(&args.output, &bundle)?;
    println!(
        "{{\"tier_n\":{},\"circuit_hash\":\"{}\"}}",
        bundle.tier_n, bundle.circuit_hash
    );
    Ok(())
}

fn strip_hex(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
}
