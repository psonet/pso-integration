//! S008 — `SpendingRecord.submit(0, ...)` reverts with `InvalidTokenId`.
//!
//! The SBT base contract guards `_mint` with `require(tokenId > 0,
//! InvalidTokenId())`. Hits agents pool, EVM execution, reverts on
//! the first storage write.

use alloy::primitives::{FixedBytes, U256};
use async_trait::async_trait;

use crate::clients::sra::into_pso_error;
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S008;

#[async_trait]
impl Scenario for S008 {
    fn id(&self) -> &'static str {
        "S008"
    }
    fn description(&self) -> &'static str {
        "SR.submit(id=0, ...) reverts with InvalidTokenId"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let err = env
        .sra_zero
        .register_spending_record(
            U256::ZERO,
            vec!["merchant".into()],
            vec![FixedBytes::from([0xa1u8; 32])],
        )
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S008: expected revert on id=0"))?;
    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::InvalidTokenId => Ok(()),
        other => Err(eyre::eyre!("S008: expected InvalidTokenId, got {other}")),
    }
}
