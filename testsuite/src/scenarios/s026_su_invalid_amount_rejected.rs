//! S026 — `SpendingUnit.submit` rejects `amount_atto >= 1e18`
//! with `InvalidAmount()`.
//!
//! The contract normalises amounts so the `atto` (fractional) slot
//! must stay strictly below 1e18 attos (one whole base unit).
//! Anything `>= 1e18` would either silently roll into the base
//! slot or violate the invariant `base + atto/1e18 == declared
//! total`; the guard fires before that ambiguity reaches storage.
//!
//! Setup mirrors S018's `mint_one_su` minus the actual mint —
//! we just register an SR, then call SU.submit directly via the
//! SRA's MintSpendingUnitArgs path with `atto = 1e18`. The
//! contract's `_validateAmount` reverts; we decode and match.

use std::time::Duration;

use alloy::primitives::FixedBytes;
use async_trait::async_trait;

use pso_l2_client::sra::MintSpendingUnitArgs;

use crate::clients::sra::into_pso_error;
use crate::data::{random_id, random_su_args};
use crate::{PsoContractError, Scenario, TestEnv};

const ONE_BASE_UNIT_IN_ATTO: u128 = 1_000_000_000_000_000_000;

pub struct S026;

#[async_trait]
impl Scenario for S026 {
    fn id(&self) -> &'static str {
        "S026"
    }
    fn description(&self) -> &'static str {
        "SU.submit with amount_atto >= 1e18 reverts InvalidAmount"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
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

    let shape = random_su_args();
    let err = env
        .sra_zero
        .mint_spending_unit(MintSpendingUnitArgs {
            su_id: random_id(),
            derived_owner: FixedBytes::from([0u8; 32]),
            currency: shape.currency,
            worldwide_day: shape.worldwide_day,
            amount_base: shape.amount_base,
            // Atto field at the exact threshold — the guard is `>=`.
            amount_atto: ONE_BASE_UNIT_IN_ATTO,
            sr_ids: vec![sr_id],
            amendment_sr_ids: vec![],
        })
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S026: expected InvalidAmount revert, got success"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::InvalidAmount => Ok(()),
        other => Err(eyre::eyre!("S026: expected InvalidAmount, got {other}")),
    }
}
