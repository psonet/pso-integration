//! S007 — re-registering the same SR id reverts with `AlreadyExists`.
//!
//! Verifies the SBT-base `_mint` guard fires on second submission.
//! Uses random keys/values per call so we know the rejection comes
//! from the id collision and not from metadata equality.

use std::time::Duration;

use alloy::primitives::FixedBytes;
use async_trait::async_trait;

use pso_l2_e2e_tests::clients::sra::into_pso_error;
use pso_l2_e2e_tests::data::{random_id, random_sr_metadata};
use pso_l2_e2e_tests::{PsoContractError, Scenario, TestEnv};

#[allow(dead_code)]
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
    let meta1 = random_sr_metadata();
    let (keys1, values1): (Vec<String>, Vec<FixedBytes<32>>) = meta1.into_iter().unzip();
    let tx1 = env
        .sra
        .register_spending_record(sr_id, keys1, values1)
        .await?;
    env.sra
        .wait_for_tx_success(tx1, Duration::from_secs(30))
        .await?;

    // Second submission with the same id but fresh metadata: must
    // revert with `AlreadyExists`. The SBT base contract guards
    // every `_mint` call.
    let meta2 = random_sr_metadata();
    let (keys2, values2): (Vec<String>, Vec<FixedBytes<32>>) = meta2.into_iter().unzip();
    let err = env
        .sra
        .register_spending_record(sr_id, keys2, values2)
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("expected duplicate SR id to revert"))?;
    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::AlreadyExists => Ok(()),
        other => Err(eyre::eyre!("expected AlreadyExists, got {other}")),
    }
}

#[tokio::test]
#[ignore = "requires a running PSO L2 node — opt-in via `cargo test -- --ignored`"]
#[serial_test::serial]
async fn s007_sr_duplicate_id_rejected() -> eyre::Result<()> {
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
