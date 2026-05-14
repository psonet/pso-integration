//! S019 — `TributeDraft.submit` rejects a 68-byte aggregation proof
//! whose declared public inputs don't match the on-chain
//! reconstruction with `InvalidAggregationProof`.
//!
//! Mirror image of S018 (`MalformedAggregationProof` on bad length).
//! Here the proof clears the structural checks:
//! - `combinedProof.length >= 68` (exactly headerLen for tier 1).
//! - `num_inputs` prefix BE-decodes to 2, matching `k`.
//! But the two declared public inputs are zero — they can't match
//! the reconstructed `(derived_owner, su_hash)` pair. The contract
//! reverts at the first mismatch with `InvalidAggregationProof`.
//!
//! This isolates the public-input-mismatch path from the SNARK
//! precompile rejection path; both surface the same error variant,
//! but the wire path differs.

use std::time::Duration;

use alloy::primitives::{Bytes, FixedBytes, U256};
use async_trait::async_trait;
use k256::SecretKey;

use pso_l2_client::abi::{ITributeDraft, TRIBUTE_DRAFT};

use crate::bridge::SuMintArgs;
use crate::clients::sra::into_pso_error;
use crate::data::{random_id, random_secret_key, random_su_args};
use crate::{PsoContractError, Scenario, TestEnv};

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

    // Tier-1 header: 4-byte BE `num_inputs = 2` + 2 × 32-byte
    // zero-filled "public inputs". Length = 68, the exact
    // `headerLen` the contract computes for k=2, so the length and
    // num_inputs checks both pass. The first input compare ((0) vs
    // the SU's real `derivedOwner`) fails -> InvalidAggregationProof.
    let mut proof = Vec::with_capacity(68);
    proof.extend_from_slice(&2u32.to_be_bytes());
    proof.extend_from_slice(&[0u8; 64]);

    let provider = env.sra.inner().write_provider()?;
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

    let typed = into_pso_error(pso_l2_client::L2ClientError::Contract(format!("{err}")));
    match &typed {
        PsoContractError::InvalidAggregationProof => Ok(()),
        other => Err(eyre::eyre!(
            "S019: expected InvalidAggregationProof, got {other}"
        )),
    }
}

async fn mint_one_su(env: &TestEnv) -> eyre::Result<U256> {
    let sr_id = random_id();
    let tx = env
        .sra
        .register_spending_record(
            sr_id,
            vec!["merchant".into()],
            vec![FixedBytes::from([0xa1u8; 32])],
        )
        .await?;
    env.sra
        .wait_for_tx_success(tx, Duration::from_secs(30))
        .await?;
    env.sra
        .wait_for_sr_existence(&[sr_id], &[], Duration::from_secs(30))
        .await?;

    let consent_sk_bytes = random_secret_key();
    let consent_sk = SecretKey::from_slice(&consent_sk_bytes)?;
    let consent_pk = consent_sk.public_key();
    let shape = random_su_args();
    let args = SuMintArgs {
        su_id: random_id(),
        consent_pk,
        currency: shape.currency,
        worldwide_day: shape.worldwide_day,
        settlement_amount_base: shape.settlement_amount_base,
        settlement_amount_atto: shape.settlement_amount_atto,
        sr_ids: vec![sr_id],
        amendment_sr_ids: vec![],
    };
    let receipt = env.bridge.mint_su(args).await?;
    env.sra
        .wait_for_su_existence(&[receipt.su_id], Duration::from_secs(30))
        .await?;
    Ok(receipt.su_id)
}
