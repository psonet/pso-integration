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
    /// Submission binding the witness signs over (32-byte hex). This is
    /// `Poseidon(sender, tributeDraftId, chainId)`; the SAME binding
    /// must be used for every witness in a TD and at `submit-td` time.
    #[arg(long)]
    pub binding: String,
    /// Output JSON path for the ownership witness.
    #[arg(long, short)]
    pub output: PathBuf,
}

pub fn run(seed: &[u8], args: Args) -> Result<()> {
    let report: IssuanceReportJson = crate::read_json(&args.report)?;
    let binding = strip_hex(&args.binding)?;

    // Re-derive the wallet's consent from the seed, then build the
    // witness for the issued NFT over the binding.
    let wallet = pso_mobile_integration::Wallet::new();
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
