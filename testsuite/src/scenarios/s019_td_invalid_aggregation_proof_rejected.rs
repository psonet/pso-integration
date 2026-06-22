//! S019 — `TributeDraft.submit` rejects a 100-byte aggregation proof
//! whose declared public inputs don't match the on-chain
//! reconstruction with `InvalidAggregationProof`.
//!
//! Mirror image of S018 (`MalformedAggregationProof` on bad length).
//! Here the proof clears the structural checks:
//! - `combinedProof.length >= 100` (exactly headerLen for tier 1, k=3).
//! - `num_inputs` prefix BE-decodes to 3 (= 2N+1), matching `k`.
//!
//! But the three declared public inputs are zero — they can't match
//! the reconstructed `(derived_owner, su_hash, binding_hash)` triple.
//! The contract reverts at the first mismatch with
//! `InvalidAggregationProof`.
//!
//! This isolates the public-input-mismatch path from the SNARK
//! precompile rejection path; both surface the same error variant,
//! but the wire path differs.

use std::time::Duration;

use alloy_primitives::{Bytes, FixedBytes, U256};
use async_trait::async_trait;

use pso_chain_abi::addresses::TRIBUTE_DRAFT;
use pso_chain_abi::interfaces::ITributeDraft;

use crate::bridge::SuMintArgs;
use crate::data::{random_id, random_su_args};
use crate::{decode_text, PsoContractError, Scenario, TestEnv};

pub struct S019;

#[async_trait]
impl Scenario for S019 {
    fn id(&self) -> &'static str {
        "S019"
    }
    fn description(&self) -> &'static str {
        "TD.submit with mismatched public inputs reverts InvalidAggregationProof"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let su_id = mint_one_su(env).await?;
    tracing::info!(scenario = "S019", step = "su-minted", %su_id, "minted SU for TD reference");

    // Tier-1 header: 4-byte BE `num_inputs = 3` (= 2N+1: two
    // (owner, nft_hash) slots + the trailing binding_hash) + 3 × 32-byte
    // zero-filled "public inputs". Length = 100, the exact `headerLen`
    // the contract computes for k=3, so the length and num_inputs checks
    // both pass. The first input compare ((0) vs the SU's real
    // `derivedOwner`) fails -> InvalidAggregationProof (not the count-based
    // MalformedAggregationProof).
    let mut proof = Vec::with_capacity(100);
    proof.extend_from_slice(&3u32.to_be_bytes());
    proof.extend_from_slice(&[0u8; 96]);

    let provider = env.attester_zero.inner().write_provider()?;
    let td = ITributeDraft::new(TRIBUTE_DRAFT, provider);

    let err = td
        .submit(
            random_id(),
            FixedBytes::from([0u8; 32]),
            vec![su_id],
            Bytes::from(proof),
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S019: expected revert on mismatched proof, got success"))?;

    let typed = decode_text(&format!("{err}"));
    match &typed {
        PsoContractError::InvalidAggregationProof => Ok(()),
        other => Err(eyre::eyre!(
            "S019: expected InvalidAggregationProof, got {other}"
        )),
    }
}

async fn mint_one_su(env: &TestEnv) -> eyre::Result<U256> {
    let sr_id = random_id();
    let tx = env.attester_zero.register_spending_record(sr_id).await?;
    env.attester_zero
        .wait_for_tx_success(tx, Duration::from_secs(30))
        .await?;
    env.attester_zero
        .wait_for_sr_existence(&[sr_id], &[], Duration::from_secs(30))
        .await?;

    let wallet = pso_mobile_integration::Wallet::new(env.chain_id);
    let consent = wallet
        .generate_consent(vec![0x19; 32])
        .map_err(|e| eyre::eyre!("consent: {e:?}"))?;
    let consent_pk = consent
        .public_key()
        .map_err(|e| eyre::eyre!("consent pk: {e:?}"))?;
    let shape = random_su_args();
    let args = SuMintArgs {
        consent_pk,
        referrer_address: alloy_primitives::Address::ZERO,
        currency: shape.currency,
        worldwide_day: shape.worldwide_day,
        amount_base: shape.amount_base,
        amount_atto: shape.amount_atto,
        sr_ids: vec![sr_id],
        amendment_sr_ids: vec![],
    };
    let receipt = env.bridge.mint_su(args).await?;
    env.attester_zero
        .wait_for_su_existence(&[receipt.su_id], Duration::from_secs(30))
        .await?;
    Ok(receipt.su_id)
}
