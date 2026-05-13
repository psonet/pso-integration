//! S011 — SU referencing a never-registered SR reverts with
//! `SpendingRecordsNotOwnedBySender`.
//!
//! The on-chain check is `srSubmittedBy(h) == _msgSender()`. For a
//! never-registered SR the `submittedBy` slot is `address(0)`, which
//! cannot equal the SRA signer; the revert fires with the same
//! variant as S009's "wrong-owner" case.

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
        "SU.submit with never-registered SR ids reverts with SpendingRecordsNotOwnedBySender"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let phantom_sr = random_id();
    let shape = random_su_args();
    let err = env
        .sra
        .mint_spending_unit(MintSpendingUnitArgs {
            su_id: random_id(),
            derived_owner: FixedBytes::from([0u8; 32]),
            settlement_currency: shape.currency,
            worldwide_day: shape.worldwide_day,
            settlement_amount_base: shape.settlement_amount_base,
            settlement_amount_atto: 0,
            sr_ids: vec![phantom_sr],
            amendment_sr_ids: vec![],
        })
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S011: expected revert on phantom SR"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::SpendingRecordsNotOwnedBySender(_, _) => Ok(()),
        other => Err(eyre::eyre!(
            "S011: expected SpendingRecordsNotOwnedBySender, got {other}"
        )),
    }
}
