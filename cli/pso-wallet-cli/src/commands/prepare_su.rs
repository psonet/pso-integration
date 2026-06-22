//! `pso-wallet-cli prepare-su` — turn an Attester-delivered issuance report
//! into an ownership witness the wallet can later aggregate.
//!
//! Reconstructs the signer from the wallet's consent material (the NFT
//! key stays encapsulated inside the FFI) and signs over the submission
//! `binding`. The output is a self-contained `NftOwnershipWitness`
//! (hex-JSON shadow) ready for `aggregate`.

use std::path::PathBuf;

use clap::Args as ClapArgs;
use eyre::Result;

use crate::artifacts::{IssuanceReportJson, OwnershipWitnessJson};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON issuance report from the Attester (see [`IssuanceReportJson`]).
    #[arg(long)]
    pub report: PathBuf,
    /// Submitter EVM address (20-byte hex) — the per-tx opaque key's EOA.
    #[arg(long)]
    pub sender: String,
    /// Tribute-draft id (32-byte hex) — the binding's commitment. The witness
    /// commits to `binding = Poseidon(DOMAIN, sender, tributeDraftId, chainId)`,
    /// computed from these + the global `--chain-id`; the SAME sender +
    /// tribute-draft-id must be used for every witness in a TD and at
    /// `aggregate` time.
    #[arg(long = "tribute-draft-id")]
    pub tribute_draft_id: String,
    /// Output JSON path for the ownership witness.
    #[arg(long, short)]
    pub output: PathBuf,
}

pub fn run(seed: &[u8], chain_id: u64, args: Args) -> Result<()> {
    let report: IssuanceReportJson = crate::read_json(&args.report)?;
    let sender = strip_hex(&args.sender)?;
    let tribute_draft_id = strip_hex(&args.tribute_draft_id)?;

    // Re-derive the wallet's consent from the seed, then build the witness for
    // the issued NFT over the binding the wallet computes from (sender,
    // tribute_draft_id, chain_id).
    let wallet = pso_mobile_integration::Wallet::new(chain_id);
    let binding = wallet
        .compute_binding(sender, tribute_draft_id)
        .map_err(|e| eyre::eyre!("compute_binding: {e:?}"))?;
    let consent = wallet
        .generate_consent(seed.to_vec())
        .map_err(|e| eyre::eyre!("generate_consent: {e:?}"))?;
    let witness = consent
        .witness(seed.to_vec(), report.into_ffi()?, binding)
        .map_err(|e| eyre::eyre!("consent witness: {e:?}"))?;

    let json = OwnershipWitnessJson::from_ffi(&witness);
    crate::write_json(&args.output, &json)?;
    println!(
        "{{\"derived_owner\":\"{}\",\"nft_hash\":\"{}\"}}",
        json.derived_owner, json.nft_hash
    );
    Ok(())
}

fn strip_hex(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
}
