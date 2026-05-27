//! S011 — SU referencing a never-registered SR reverts with
//! `InvalidSpendingRecords` (bad-owner SR arm).
//!
//! The on-chain check is `!exists(h) || ownerOf(h) != _msgSender()`.
//! For a never-registered SR `exists(h) == false` short-circuits the
//! check; the revert fires with the same arm as S009's wrong-owner
//! case (first field of `InvalidSpendingRecords`).

use alloy::primitives::FixedBytes;
use async_trait::async_trait;

use pso_l2_client::sra::MintSpendingUnitArgs;

use crate::clients::sra::into_pso_error;
use crate::data::{random_id, random_su_args};
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S011;

#[async_trait]
impl Scenario for S011 {
    fn id(&self) -> &'static str {
        "S011"
    }
    fn description(&self) -> &'static str {
        "SU.submit with never-registered SR ids reverts with InvalidSpendingRecords (bad-owner SR)"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let phantom_sr = random_id();
    let shape = random_su_args();
    let err = env
        .sra_zero
        .mint_spending_unit(MintSpendingUnitArgs {
            su_id: random_id(),
            derived_owner: FixedBytes::from([0u8; 32]),
            currency: shape.currency,
            worldwide_day: shape.worldwide_day,
            amount_base: shape.amount_base,
            amount_atto: 0,
            sr_ids: vec![phantom_sr],
            amendment_sr_ids: vec![],
        })
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S011: expected revert on phantom SR"))?;

    let typed = into_pso_error(err);
    match &typed {
        // Nonexistent SR fails the `exists()` guard → bad-owner SR arm
        // (first field). The other three arms should be empty, but we
        // don't assert that — the contract may evolve.
        PsoContractError::InvalidSpendingRecords(bad_srs, _, _, _) if !bad_srs.is_empty() => Ok(()),
        other => Err(eyre::eyre!(
            "S011: expected InvalidSpendingRecords with bad-owner SR, got {other}"
        )),
    }
}
