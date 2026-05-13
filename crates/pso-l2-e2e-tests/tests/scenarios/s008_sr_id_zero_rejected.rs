//! S008 — `SpendingRecord.submit(0, ...)` reverts with `InvalidTokenId`.
//!
//! The SBT base contract guards `_mint` with `require(tokenId > 0,
//! InvalidTokenId())`. Hits agents pool, EVM execution, reverts on
//! the first storage write.

use alloy::primitives::{FixedBytes, U256};
use async_trait::async_trait;

use pso_l2_e2e_tests::clients::sra::into_pso_error;
use pso_l2_e2e_tests::{PsoContractError, Scenario, TestEnv};

#[allow(dead_code)]
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
        .sra
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

#[tokio::test]
#[ignore = "requires a running PSO L2 node — opt-in via `cargo test -- --ignored`"]
#[serial_test::serial]
async fn s008_sr_id_zero_rejected() -> eyre::Result<()> {
    pso_l2_e2e_tests::env::init_tracing();
    // Per-scenario test bootstraps its own env: when this file is
    // also included into the  binary via #[path] we end up
    // with two #[tokio::test]s — the runner sets up the shared env in
    // its own tokio runtime, then this body runs under a *fresh*
    // runtime that has already torn down the bridge background task
    // owned by the cached env. Bootstrap-per-call is the simplest
    // path that keeps both binaries green; the bootstrap step is
    // idempotent and the extra ~5s is acceptable for the 12-scenario
    // standalone surface.
    let env = TestEnv::bootstrap().await?;
    run(&env).await
}
