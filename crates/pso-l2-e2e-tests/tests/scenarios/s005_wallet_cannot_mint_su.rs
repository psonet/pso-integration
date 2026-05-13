//! S005 — wallet (non-SRA) cannot mint an SU via the actor pool.
//!
//! Same shape as S003 / S004, addressed at `SpendingUnit.submit`.
//! Same two-path acceptance documented in S003's body.

use std::time::Duration;

use alloy::primitives::{Bytes, FixedBytes};
use alloy::sol_types::SolCall;
use async_trait::async_trait;

use pso_l2_client::abi::{ISpendingUnit, SPENDING_UNIT};

use pso_l2_e2e_tests::clients::actor::ActorClientError;
use pso_l2_e2e_tests::data::{random_id, random_su_args};
use pso_l2_e2e_tests::{PsoContractError, Scenario, TestEnv};

#[allow(dead_code)]
pub struct S005;

#[async_trait]
impl Scenario for S005 {
    fn id(&self) -> &'static str {
        "S005"
    }
    fn description(&self) -> &'static str {
        "non-SRA wallet cannot mint a SpendingUnit through the actor pool"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let su_id = random_id();
    let shape = random_su_args();
    let call = ISpendingUnit::submitCall {
        suId: su_id,
        derivedOwner: FixedBytes::from([0u8; 32]),
        settlementCurrency: shape.currency,
        worldwideDay: shape.worldwide_day,
        settlementAmountBase: shape.settlement_amount_base,
        settlementAmountAtto: shape.settlement_amount_atto,
        srIds: vec![random_id()],
        amendmentSrIds: vec![],
    };
    let inner = Bytes::from(call.abi_encode());

    match env.actor.submit_tx(SPENDING_UNIT, inner).await {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, "S005: actor pool refused tx (no SU minted)");
            Ok(())
        }
        Err(ActorClientError::Revert(PsoContractError::SRANotActive)) => Ok(()),
        Err(other) => {
            tracing::info!(?other, "S005: actor surfaced typed error");
            Ok(())
        }
        Ok(tx_hash) => {
            let receipt = env
                .actor
                .wait_for_receipt(tx_hash, Duration::from_secs(30))
                .await?;
            if receipt.status() {
                Err(eyre::eyre!(
                    "S005: wallet-signed SU.submit succeeded — invariant violated"
                ))
            } else {
                tracing::info!(?tx_hash, "S005: actor admitted tx, EVM reverted (status=0)");
                Ok(())
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires a running PSO L2 node — opt-in via `cargo test -- --ignored`"]
#[serial_test::serial]
async fn s005_wallet_cannot_mint_su() -> eyre::Result<()> {
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
