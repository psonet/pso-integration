//! S024 — `TributeDraft.submit` rejects an SU count that isn't a
//! canonical aggregation tier with `AggregationTierUnavailable(n)`.
//!
//! Canonical tier set (from `_selectTier` in TributeDraft.sol and
//! `pso_zk_canonical::SU_AGGREGATION_TIERS`):
//! `{1, 2, 4, 8, 16, 32, 64}`. Any other `n` triggers
//! `AggregationTierUnavailable(n)`. The contract still does the
//! per-SU `_collectSuTotals` walk first, so each suId must point
//! at a real SU to make this scenario hit the right revert.
//!
//! Approach: mint 3 SUs (same day + currency so the prior gates
//! pass), submit TD with `suIds.len() == 3`. The contract walks
//! the array, sums amounts, then calls `_selectTier(3)` which has
//! no case for n=3 and reverts. The payload's encoded `suCount`
//! field MUST be 3.

use std::time::Duration;

use alloy::primitives::U256;
use alloy::primitives::{Bytes, FixedBytes};
use async_trait::async_trait;
use k256::SecretKey;

use pso_l2_client::abi::{ITributeDraft, TRIBUTE_DRAFT};

use crate::bridge::SuMintArgs;
use crate::clients::sra::into_pso_error;
use crate::data::{random_id, random_secret_key, random_su_args};
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S024;

#[async_trait]
impl Scenario for S024 {
    fn id(&self) -> &'static str {
        "S024"
    }
    fn description(&self) -> &'static str {
        "TD.submit with non-canonical SU count reverts AggregationTierUnavailable(n)"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let shape = random_su_args();
    let mut su_ids = Vec::with_capacity(3);
    for _ in 0..3 {
        let id = mint_su_with(
            env,
            shape.currency,
            shape.worldwide_day,
            shape.settlement_amount_base,
        )
        .await?;
        su_ids.push(id);
    }
    tracing::info!(
        scenario = "S024",
        count = 3,
        "minted three SUs (not a canonical tier)"
    );

    let provider = env.sra.inner().write_provider()?;
    let td = ITributeDraft::new(TRIBUTE_DRAFT, provider);

    let err = td
        .submit(
            random_id(),
            FixedBytes::from([0u8; 32]),
            su_ids.clone(),
            Bytes::new(),
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S024: expected AggregationTierUnavailable, got success"))?;

    let typed = into_pso_error(pso_l2_client::L2ClientError::Contract(format!("{err}")));
    match &typed {
        PsoContractError::AggregationTierUnavailable(n) => {
            if *n != 3 {
                return Err(eyre::eyre!(
                    "S024: AggregationTierUnavailable count mismatch: got {n}, expected 3"
                ));
            }
            Ok(())
        }
        other => Err(eyre::eyre!(
            "S024: expected AggregationTierUnavailable(_), got {other}"
        )),
    }
}

async fn mint_su_with(
    env: &TestEnv,
    currency: u16,
    worldwide_day: u32,
    base: u64,
) -> eyre::Result<U256> {
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

    let consent_sk = SecretKey::from_slice(&random_secret_key())?;
    let receipt = env
        .bridge
        .mint_su(SuMintArgs {
            su_id: random_id(),
            consent_pk: consent_sk.public_key(),
            currency,
            worldwide_day,
            settlement_amount_base: base,
            settlement_amount_atto: 0,
            sr_ids: vec![sr_id],
            amendment_sr_ids: vec![],
        })
        .await?;
    env.sra
        .wait_for_su_existence(&[receipt.su_id], Duration::from_secs(30))
        .await?;
    Ok(receipt.su_id)
}
