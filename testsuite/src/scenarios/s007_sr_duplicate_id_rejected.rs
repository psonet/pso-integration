//! S007 — re-registering the same SR id reverts with `AlreadyExists`.
//!
//! Verifies the SBT-base `_mint` guard fires on second submission.
//! SR carries no metadata under the commitment-token model — the id
//! itself is the only thing that can collide.

use std::time::Duration;

use async_trait::async_trait;

use crate::clients::sra::into_pso_error;
use crate::data::random_id;
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S007;

#[async_trait]
impl Scenario for S007 {
    fn id(&self) -> &'static str {
        "S007"
    }
    fn description(&self) -> &'static str {
        "registering the same SR id twice reverts with AlreadyExists"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let sr_id = random_id();

    // First submission: must land.
    let tx1 = env
        .sra_zero
        .register_spending_record(sr_id)
        .await?;
    env.sra_zero
        .wait_for_tx_success(tx1, Duration::from_secs(30))
        .await?;

    // Second submission with the same id: must revert with
    // `AlreadyExists`. The SBT base contract guards every `_mint` call.
    let err = env
        .sra_zero
        .register_spending_record(sr_id)
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("expected duplicate SR id to revert"))?;
    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::AlreadyExists => Ok(()),
        other => Err(eyre::eyre!("expected AlreadyExists, got {other}")),
    }
}
