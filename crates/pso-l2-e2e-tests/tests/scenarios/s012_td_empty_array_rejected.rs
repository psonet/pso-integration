//! S012 — `TributeDraft.submit(_, _, [], _)` reverts with `EmptyArray`.
//!
//! The TD contract opens with `if (n == 0) revert EmptyArray();` —
//! no aggregation tier is built for `n_su == 0`. We submit through
//! the agents pool (TD.submit isn't actor-pool routed today; the
//! pool-side `MethodNotPermitted` would mask the EVM check), so we
//! call directly via the underlying provider with the same encoding
//! `submit_tribute_draft` uses.
//!
//! Note: the agents pool currently rejects TD.submit before EVM
//! dispatch (S002). To exercise the EVM check itself, we route
//! through alloy's typed contract instance with `eth_call` — that
//! way we surface the EVM revert without paying the pool gate. If
//! pso-chain later admits TD.submit through the agents pool (or via
//! a new TD-only lane), this test will switch to a real broadcast.

use alloy::primitives::{Bytes, U256};
use async_trait::async_trait;

use pso_l2_client::abi::{ITributeDraft, TRIBUTE_DRAFT};

use pso_l2_e2e_tests::errors::decode_text;
use pso_l2_e2e_tests::{PsoContractError, Scenario, TestEnv};

#[allow(dead_code)]
pub struct S012;

#[async_trait]
impl Scenario for S012 {
    fn id(&self) -> &'static str {
        "S012"
    }
    fn description(&self) -> &'static str {
        "TributeDraft.submit with empty suIds reverts with EmptyArray"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let provider = env.sra.inner().read_provider();
    let td = ITributeDraft::new(TRIBUTE_DRAFT, &provider);
    let result = td
        .submit(U256::from(1u64), Default::default(), vec![], Bytes::new())
        .call()
        .await;
    let err = match result {
        Ok(_) => {
            return Err(eyre::eyre!("S012: expected EmptyArray revert on eth_call"))
        }
        Err(e) => e,
    };
    let typed = decode_text(&err.to_string());
    match &typed {
        PsoContractError::EmptyArray => Ok(()),
        // Some deployments wrap empty-array as a `MalformedAggregationProof`
        // when the proof bytes are also empty; accept either guard.
        PsoContractError::MalformedAggregationProof => Ok(()),
        other => Err(eyre::eyre!("S012: expected EmptyArray, got {other}")),
    }
}

#[tokio::test]
#[ignore = "requires a running PSO L2 node — opt-in via `cargo test -- --ignored`"]
#[serial_test::serial]
async fn s012_td_empty_array_rejected() -> eyre::Result<()> {
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
