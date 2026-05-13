//! S004 — wallet (non-SRA) cannot register an AR via the actor pool.
//!
//! Same shape as S003, addressed at `SpendingRecordAmendment.submit`.
//! See S003's body for the documented two-path acceptance.

use std::time::Duration;

use alloy::primitives::Bytes;
use alloy::sol_types::SolCall;
use async_trait::async_trait;

use pso_l2_client::abi::{ISpendingRecordAmendment, SPENDING_RECORD_AMENDMENT};

use pso_l2_e2e_tests::clients::actor::ActorClientError;
use pso_l2_e2e_tests::data::random_id;
use pso_l2_e2e_tests::{PsoContractError, Scenario, TestEnv};

#[allow(dead_code)]
pub struct S004;

#[async_trait]
impl Scenario for S004 {
    fn id(&self) -> &'static str {
        "S004"
    }
    fn description(&self) -> &'static str {
        "non-SRA wallet cannot submit a SpendingRecordAmendment through the actor pool"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let ar_id = random_id();
    let call = ISpendingRecordAmendment::submitCall {
        srId: ar_id,
        keys: vec!["correction".into()],
        values: vec![Default::default()],
    };
    let inner = Bytes::from(call.abi_encode());

    match env.actor.submit_tx(SPENDING_RECORD_AMENDMENT, inner).await {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, "S004: actor pool refused tx (no AR landed)");
            Ok(())
        }
        Err(ActorClientError::Revert(PsoContractError::SRANotActive)) => Ok(()),
        Err(other) => {
            tracing::info!(?other, "S004: actor surfaced typed error");
            Ok(())
        }
        Ok(tx_hash) => {
            let receipt = env
                .actor
                .wait_for_receipt(tx_hash, Duration::from_secs(30))
                .await?;
            if receipt.status() {
                Err(eyre::eyre!(
                    "S004: wallet-signed AR.submit succeeded — invariant violated"
                ))
            } else {
                tracing::info!(?tx_hash, "S004: actor admitted tx, EVM reverted (status=0)");
                Ok(())
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires a running PSO L2 node — opt-in via `cargo test -- --ignored`"]
#[serial_test::serial]
async fn s004_wallet_cannot_register_ar() -> eyre::Result<()> {
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
