//! S010 — two SUs sharing one SR fingerprint trips the
//! double-spend guard.
//!
//! `SpendingUnit.submit` tracks `usedSpendingRecordIds[sr]` and
//! reverts on the second mint with
//! `SpendingRecordsAlreadyExist(srHashes, amendmentSrHashes)`.

use std::time::Duration;

use alloy::primitives::{FixedBytes, U256};
use async_trait::async_trait;

use pso_l2_client::sra::MintSpendingUnitArgs;

use crate::clients::sra::into_pso_error;
use crate::data::{random_id, random_su_args};
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S010;

#[async_trait]
impl Scenario for S010 {
    fn id(&self) -> &'static str {
        "S010"
    }
    fn description(&self) -> &'static str {
        "second SU sharing an SR fingerprint reverts with SpendingRecordsAlreadyExist"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // Register a single SR; both SU mints will reference it.
    let sr_id = random_id();
    let tx = env
        .sra_zero
        .register_spending_record(
            sr_id,
            vec!["merchant".into()],
            vec![FixedBytes::from([0xa1u8; 32])],
        )
        .await?;
    env.sra_zero
        .wait_for_tx_success(tx, Duration::from_secs(30))
        .await?;
    env.sra_zero
        .wait_for_sr_existence(&[sr_id], &[], Duration::from_secs(30))
        .await?;

    // First SU mint must succeed.
    let shape = random_su_args();
    let su1_id = random_id();
    let tx = env
        .sra_zero
        .mint_spending_unit(MintSpendingUnitArgs {
            su_id: su1_id,
            derived_owner: FixedBytes::from([0u8; 32]),
            settlement_currency: shape.currency,
            worldwide_day: shape.worldwide_day,
            settlement_amount_base: shape.settlement_amount_base,
            settlement_amount_atto: 0,
            sr_ids: vec![sr_id],
            amendment_sr_ids: vec![],
        })
        .await?;
    env.sra_zero
        .wait_for_tx_success(tx, Duration::from_secs(30))
        .await?;

    // Second SU mint with the same SR — the contract's
    // `usedSpendingRecordIds` map collides; expect
    // `SpendingRecordsAlreadyExist`.
    let su2_id = random_id();
    let err = env
        .sra_zero
        .mint_spending_unit(MintSpendingUnitArgs {
            su_id: su2_id,
            derived_owner: FixedBytes::from([0u8; 32]),
            settlement_currency: shape.currency,
            worldwide_day: shape.worldwide_day,
            settlement_amount_base: shape.settlement_amount_base,
            settlement_amount_atto: 0,
            sr_ids: vec![sr_id],
            amendment_sr_ids: vec![],
        })
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S010: expected double-spend revert"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::SpendingRecordsAlreadyExist(srs, _ars) => {
            // The contract returns the colliding hashes; assert
            // our sr_id is in there.
            let observed: Vec<U256> = srs.clone();
            if !observed.contains(&sr_id) {
                return Err(eyre::eyre!(
                    "S010: SR id missing from error payload; got {typed}"
                ));
            }
            Ok(())
        }
        other => Err(eyre::eyre!(
            "S010: expected SpendingRecordsAlreadyExist, got {other}"
        )),
    }
}
