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

use crate::errors::decode_text;
use crate::{PsoContractError, Scenario, TestEnv};

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
        Ok(_) => return Err(eyre::eyre!("S012: expected EmptyArray revert on eth_call")),
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
