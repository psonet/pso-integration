//! `pso-wallet-cli aggregate` — fold N per-SU ownership proofs into
//! one recursive aggregation proof.
//!
//! Per the spec redesign (`docs/aggregation-redesign.md`):
//!
//! 1. Load each SU's `SuOwnershipWitness` (produced by `prepare-su`).
//! 2. Generate one inner SU-ownership proof per witness via
//!    `prove_su_ownership`.
//! 3. Fold the N inner proofs into one recursive proof via
//!    `aggregate_su_proofs`.
//! 4. Pair with the wallet-rolled TD keypair to produce the
//!    `AggregationProofBundle` ready for `submit-td`.
//!
//! Until the Noir circuit work in `pso-zk-circuits` lands, steps
//! 2–3 surface `L2ClientError::CircuitNotAvailable`. The CLI command
//! still parses inputs and runs steps 1 + 4 (the TD material roll
//! and JSON I/O) so callers can exercise the data plumbing.

use std::path::PathBuf;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use clap::Args as ClapArgs;
use eyre::Result;
use pso_l2_client::wallet::{
    aggregate_su_proofs, prepare_td_keypair, prove_su_ownership, AggregationRequest,
    SuOwnershipProof, SuOwnershipWitness,
};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON files produced by `prepare-su` — one per SU being
    /// aggregated.
    #[arg(long, num_args = 1..)]
    pub witnesses: Vec<PathBuf>,
    /// `su_hash` per witness, in the same order. 32-byte LE Fr hex,
    /// comma-separated. Each value is the off-chain-computed entity
    /// hash of the corresponding SU per §3.2.2 (delivered to the
    /// wallet alongside the SU data, or recomputed locally if the
    /// wallet has the full SU envelope).
    #[arg(long)]
    pub su_hashes: String,
    /// Output JSON path for the wallet-rolled TD material (kept for
    /// Phase 2 — the post-mint TD ownership proof).
    #[arg(long)]
    pub td_material_out: PathBuf,
    /// Output JSON path for the aggregation bundle.
    #[arg(long)]
    pub output: PathBuf,
}

pub fn run(_consent_key: &[u8; 32], _chain_id: u64, args: Args) -> Result<()> {
    let witnesses: Vec<SuOwnershipWitness> = args
        .witnesses
        .iter()
        .map(crate::read_json::<SuOwnershipWitness>)
        .collect::<Result<_>>()?;
    let su_hashes = parse_fr_le_list(&args.su_hashes)?;

    if witnesses.len() != su_hashes.len() {
        eyre::bail!(
            "witnesses ({}) and su_hashes ({}) must be parallel",
            witnesses.len(),
            su_hashes.len()
        );
    }

    // Step 1+2: produce one inner proof per SU. Currently errors
    // with `CircuitNotAvailable` — the per-SU ownership circuit
    // needs the §4.2 rewrite. Once that lands these calls go live.
    let proofs: Vec<SuOwnershipProof> = witnesses
        .iter()
        .zip(su_hashes.iter())
        .map(|(w, h)| prove_su_ownership(w, *h))
        .collect::<Result<_, _>>()?;

    // Step 3: roll the TD material the wallet keeps for Phase 2.
    let td_material = prepare_td_keypair()?;
    crate::write_json(&args.td_material_out, &td_material)?;

    // Step 4: fold inner proofs via the recursion circuit. Also
    // currently errors out — the recursion circuit isn't in
    // pso-zk-circuits yet.
    let mut td_owner_bytes = [0u8; 32];
    let td_owner_vec = strip_hex(&td_material.td_derived_owner_le_hex)?;
    if td_owner_vec.len() != 32 {
        eyre::bail!("td_derived_owner must be 32 bytes");
    }
    td_owner_bytes.copy_from_slice(&td_owner_vec);

    let bundle = aggregate_su_proofs(AggregationRequest {
        su_proofs: &proofs,
        td_derived_owner_le: td_owner_bytes,
    })?;
    crate::write_json(&args.output, &bundle)?;
    println!(
        "{{\"tier_n\":{},\"label\":\"{}\",\"tribute_draft_id\":\"{}\"}}",
        bundle.tier.tier_n, bundle.tier.label, bundle.tribute_draft_id
    );
    Ok(())
}

fn parse_fr_le_list(s: &str) -> Result<Vec<Fr>> {
    s.split(',')
        .map(|tok| {
            let bytes = strip_hex(tok.trim())?;
            if bytes.len() != 32 {
                eyre::bail!("Fr LE hex must be 32 bytes, got {}", bytes.len());
            }
            Ok(Fr::from_le_bytes_mod_order(&bytes))
        })
        .collect()
}

fn strip_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}
