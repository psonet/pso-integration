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
    /// JSON witnesses produced by `prepare-su` — one per SU. Every witness must
    /// commit to the binding the wallet recomputes from `--sender` +
    /// `--tribute-draft-id` (+ the global `--chain-id`).
    #[arg(long, num_args = 1..)]
    pub witnesses: Vec<PathBuf>,
    /// Submitter EVM address (20-byte hex) — the per-tx opaque key's EOA.
    #[arg(long)]
    pub sender: String,
    /// Tribute-draft id (32-byte hex) — the binding's commitment.
    #[arg(long = "tribute-draft-id")]
    pub tribute_draft_id: String,
    /// Output JSON path for the aggregation bundle.
    #[arg(long, short)]
    pub output: PathBuf,
}

pub fn run(seed: &[u8], chain_id: u64, args: Args) -> Result<()> {
    let sender = strip_hex(&args.sender)?;
    let tribute_draft_id = strip_hex(&args.tribute_draft_id)?;
    let witnesses: Vec<pso_mobile_integration::NftOwnershipWitness> = args
        .witnesses
        .iter()
        .map(|p| {
            let json: OwnershipWitnessJson = crate::read_json(p)?;
            json.into_ffi()
        })
        .collect::<Result<_>>()?;

    // The wallet recomputes the binding from (sender, tribute_draft_id, chain_id);
    // the witnesses must have been built with the same value (see `prepare-su`).
    let wallet = pso_mobile_integration::Wallet::new(chain_id);
    let result = wallet
        .prove_ownership(seed.to_vec(), sender, tribute_draft_id, witnesses)
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
