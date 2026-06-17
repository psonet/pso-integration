//! `pso-wallet-cli aggregate` -- build a flat-aggregation proof from
//! N per-SU witnesses.
//!
//! Per the spec (sec. 2.2.6 + 5.2):
//!
//! 1. Load each SU's `SuOwnershipWitness` (produced by `prepare-su`).
//! 2. Roll the wallet's TD-level Grumpkin keypair + nonce.
//! 3. Call `prove_su_aggregation` -- one flat-aggregation prove pass
//!    against the chosen tier's canonical VK. No per-SU intermediate
//!    proofs; the per-SU constraint set is duplicated inline.
//! 4. Write the resulting `AggregationProofBundle` ready for
//!    `submit-td`, plus the TD material the wallet keeps for Phase 2
//!    (the post-mint TD ownership proof).

use std::path::PathBuf;

use alloy::primitives::{Address, U256};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use clap::Args as ClapArgs;
use eyre::Result;
use pso_l2_client::wallet::{
    prepare_td_keypair, prove_su_aggregation, SuAggregationInput, SuOwnershipWitness,
};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON files produced by `prepare-su` -- one per SU being
    /// aggregated. Each carries the Grumpkin sk, nonce, and
    /// `derivedOwner` the wallet stored at receipt time.
    #[arg(long, num_args = 1..)]
    pub witnesses: Vec<PathBuf>,
    /// SU entity hash per witness, in the same order. 32-byte LE Fr
    /// hex, comma-separated. Each value is the off-chain-computed
    /// `compute_spending_unit_hash(...)` of the corresponding SU
    /// (sec. 3.2.3), or fetched from canonical on-chain state via the
    /// SU-hash precompile.
    #[arg(long)]
    pub su_hashes: String,
    /// Output JSON path for the wallet-rolled TD material (kept for
    /// Phase 2 -- the post-mint TD ownership proof).
    #[arg(long)]
    pub td_material_out: PathBuf,
    /// Output JSON path for the aggregation bundle.
    #[arg(long)]
    pub output: PathBuf,
    /// The EVM address the TD will be submitted from (`msg.sender`). The
    /// proof's `binding_hash = Poseidon4(sender, tributeDraftId, chainId)`
    /// commits to it, so the SAME key must sign the eventual `submit-td`.
    #[arg(long)]
    pub sender: Address,
}

pub fn run(_consent_key: &[u8; 32], chain_id: u64, args: Args) -> Result<()> {
    let witnesses: Vec<SuOwnershipWitness> = args
        .witnesses
        .iter()
        .map(crate::read_json::<SuOwnershipWitness>)
        .collect::<Result<_>>()?;
    let su_hashes = parse_fr_be_list(&args.su_hashes)?;

    if witnesses.len() != su_hashes.len() {
        eyre::bail!(
            "witnesses ({}) and su_hashes ({}) must be parallel",
            witnesses.len(),
            su_hashes.len()
        );
    }

    // Step 1: roll the TD material the wallet keeps for Phase 2.
    let td_material = prepare_td_keypair()?;
    crate::write_json(&args.td_material_out, &td_material)?;

    // Step 2: assemble the per-SU inputs.
    let inputs: Vec<SuAggregationInput> = witnesses
        .iter()
        .zip(su_hashes.iter())
        .map(|(w, h)| {
            let sk = decode_hex32(&w.shared_sk_hex)?;
            let nonce_arr = decode_hex32(&w.su_nonce_hex)?;
            let owner_arr = decode_hex32(&w.derived_owner_be_hex)?;
            Ok::<_, eyre::Report>(SuAggregationInput {
                su_id: w.su_id.clone(),
                grumpkin_sk: sk,
                nonce: Fr::from_be_bytes_mod_order(&nonce_arr),
                derived_owner: Fr::from_be_bytes_mod_order(&owner_arr),
                nft_hash: *h,
            })
        })
        .collect::<Result<_>>()?;

    // Step 3: prove. One pass; chosen tier picks the smallest size
    // >= witnesses.len().
    let td_id_bytes = decode_hex32(&td_material.td_derived_owner_be_hex)?;
    let td_id = U256::from_be_bytes(td_id_bytes);
    let td_owner_fr =
        Fr::from_be_bytes_mod_order(&decode_hex32(&td_material.td_derived_owner_be_hex)?);
    let bundle = prove_su_aggregation(&inputs, td_id, td_owner_fr, args.sender, chain_id)?;
    crate::write_json(&args.output, &bundle)?;
    println!(
        "{{\"tier_n\":{},\"label\":\"{}\",\"tribute_draft_id\":\"{}\"}}",
        bundle.tier.tier_n, bundle.tier.label, bundle.tribute_draft_id
    );
    Ok(())
}

fn parse_fr_be_list(s: &str) -> Result<Vec<Fr>> {
    s.split(',')
        .map(|tok| {
            let bytes = decode_hex32(tok.trim())?;
            Ok(Fr::from_be_bytes_mod_order(&bytes))
        })
        .collect()
}

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        eyre::bail!("expected 32 bytes hex, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
