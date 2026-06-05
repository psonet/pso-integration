//! S020 — `SpendingUnit.submit` rejects an AR owned by a different
//! SRA in its `amendmentSrHashes` array.
//!
//! Mirrors S009 (which exercises the same invariant for `srHashes`)
//! against the amendment-record side. The privacy spec requires
//! every fingerprint in EITHER array to be owned by `msg.sender`;
//! the contract's `_validateRecordOwnershipAndUniqueness` walks
//! both arrays and bundles offenders into a single
//! `InvalidSpendingRecords(badOwnerSRs, badOwnerARs, duplicateSRs, duplicateARs)`
//! payload.
//!
//! Approach:
//! 1. Primary SRA registers an AR (via
//!    `SpendingRecordAmendment.submit`).
//! 2. Admin promotes a second SRA via
//!    [`TestEnv::register_random_sra`].
//! 3. SRA#2 attempts to mint an SU referencing SRA#1's AR in
//!    `amendment_sr_ids`. Expect
//!    `InvalidSpendingRecords(_, [ar_id], _, _)` — the AR id must
//!    appear in the bad-owner AR slot of the payload, NOT in the
//!    SR slot.

use std::time::Duration;

use alloy::primitives::FixedBytes;
use async_trait::async_trait;

use pso_l2_client::sra::MintSpendingUnitArgs;

use crate::clients::sra::into_pso_error;
use crate::data::{random_id, random_su_args};
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S020;

#[async_trait]
impl Scenario for S020 {
    fn id(&self) -> &'static str {
        "S020"
    }
    fn description(&self) -> &'static str {
        "SU.submit referencing another SRA's AR reverts with InvalidSpendingRecords (bad-owner AR)"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // SRA#1 (env.sra_zero) registers an AR.
    let ar_id = random_id();
    let tx = env
        .sra_zero
        .register_amendment_record(ar_id)
        .await?;
    env.sra_zero
        .wait_for_tx_success(tx, Duration::from_secs(30))
        .await?;
    env.sra_zero
        .wait_for_sr_existence(&[], &[ar_id], Duration::from_secs(30))
        .await?;
    tracing::info!(scenario = "S020", step = "seeded-ar", ar_id = %ar_id, "AR registered under primary SRA");

    // SRA#2 takes over and tries to bundle SRA#1's AR.
    let sra2 = env.new_sra().await?;
    let shape = random_su_args();
    let err = sra2
        .mint_spending_unit(MintSpendingUnitArgs {
            su_id: random_id(),
            derived_owner: FixedBytes::from([0u8; 32]),
            referrer_address: alloy::primitives::Address::ZERO,
            currency: shape.currency,
            worldwide_day: shape.worldwide_day,
            amount_base: shape.amount_base,
            amount_atto: shape.amount_atto,
            sr_ids: vec![],
            amendment_sr_ids: vec![ar_id],
        })
        .await
        .err()
        .ok_or_else(|| {
            eyre::eyre!("S020: expected InvalidSpendingRecords (bad-owner AR) revert")
        })?;

    let typed = into_pso_error(err);
    match &typed {
        // Foreign AR exists but is owned by a different SRA → lands
        // in the bad-owner AR arm (second field).
        PsoContractError::InvalidSpendingRecords(bad_srs, bad_ars, _, _) => {
            if !bad_ars.contains(&ar_id) {
                return Err(eyre::eyre!(
                    "S020: AR id missing from bad-owner AR slot of error payload; \
                     got bad_srs={bad_srs:?}, bad_ars={bad_ars:?}"
                ));
            }
            tracing::info!(
                scenario = "S020",
                "actor pool revert decoded; AR fingerprint reported"
            );
            Ok(())
        }
        other => Err(eyre::eyre!(
            "S020: expected InvalidSpendingRecords with bad-owner AR, got {other}"
        )),
    }
}
