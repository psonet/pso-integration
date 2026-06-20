//! S009 — Attester#2 cannot mint an SU referencing Attester#1's SR.
//!
//! Two distinct Attesters are active simultaneously. Attester#1 (the env's
//! primary Attester) registers an SR; admin promotes a freshly rolled
//! second Attester via [`TestEnv::register_random_attester`]. Attester#2 then tries
//! to mint an SU referencing Attester#1's SR. The on-chain
//! `_validateSenderOwnership` step compares `srSubmittedBy == sender`
//! and reverts with `InvalidSpendingRecords (bad-owner SR)(...)`.

use std::time::Duration;

use alloy_primitives::FixedBytes;
use async_trait::async_trait;

use crate::clients::attester::{into_pso_error, MintSpendingUnitArgs};
use crate::data::{random_id, random_su_args};
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S009;

#[async_trait]
impl Scenario for S009 {
    fn id(&self) -> &'static str {
        "S009"
    }
    fn description(&self) -> &'static str {
        "SU.submit referencing another Attester's SR reverts with InvalidSpendingRecords (bad-owner SR)"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // Attester#1 (the default `env.attester_zero`) registers an SR.
    let sr_id = random_id();
    let tx = env.attester_zero.register_spending_record(sr_id).await?;
    env.attester_zero
        .wait_for_tx_success(tx, Duration::from_secs(30))
        .await?;
    env.attester_zero
        .wait_for_sr_existence(&[sr_id], &[], Duration::from_secs(30))
        .await?;

    // Admin promotes a fresh secret-key address to active Attester, then
    // Attester#2 attempts to mint an SU referencing Attester#1's SR.
    let attester2 = env.new_attester().await?;
    let shape = random_su_args();
    let err = attester2
        .mint_spending_unit(MintSpendingUnitArgs {
            su_id: random_id(),
            derived_owner: FixedBytes::from([0u8; 32]),
            referrer_address: alloy_primitives::Address::ZERO,
            currency: shape.currency,
            worldwide_day: shape.worldwide_day,
            amount_base: shape.amount_base,
            amount_atto: shape.amount_atto,
            sr_ids: vec![sr_id],
            amendment_sr_ids: vec![],
        })
        .await
        .err()
        .ok_or_else(|| {
            eyre::eyre!("S009: expected InvalidSpendingRecords (bad-owner SR) revert")
        })?;

    let typed = into_pso_error(err);
    match &typed {
        // Foreign SR exists but is owned by a different Attester → lands in
        // the bad-owner SR arm (first field).
        PsoContractError::InvalidSpendingRecords(bad_srs, _, _, _) => {
            if !bad_srs.contains(&sr_id) {
                return Err(eyre::eyre!(
                    "S009: SR id missing from bad-owner SR slot; got {typed}"
                ));
            }
            Ok(())
        }
        other => Err(eyre::eyre!(
            "S009: expected InvalidSpendingRecords with bad-owner SR, got {other}"
        )),
    }
}
