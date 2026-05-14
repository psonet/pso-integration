//! S015 — actor RPC rejects an envelope claiming a `submitted_block`
//! far in the past.
//!
//! The PSO header includes an 8-byte `submitted_block` (BE) at
//! bytes 164..172. The chain accepts a small backward window around
//! head (`MAX_BATCH_DELAY` / `proof_validity_window`); anything
//! older is a stale-or-forged envelope and the pool rejects it.
//!
//! We mutate the slot to `head - 10_000` and expect a
//! `PoolRejection`. The rest of the header (magic / VDF binding /
//! proof) stays consistent with the *original* `submitted_block`
//! the envelope was built against, so the chain has multiple
//! reasons to bounce this — but the staleness check fires first.

use alloy::primitives::Bytes;
use alloy::sol_types::SolCall;
use async_trait::async_trait;

use pso_l2_client::abi::{ISpendingRecord, SPENDING_RECORD};

use crate::clients::actor::ActorClientError;
use crate::data::random_id;
use crate::{Scenario, TestEnv};

pub struct S015;

#[async_trait]
impl Scenario for S015 {
    fn id(&self) -> &'static str {
        "S015"
    }
    fn description(&self) -> &'static str {
        "actor RPC rejects envelope with stale submitted_block"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let sr_id = random_id();
    let call = ISpendingRecord::submitCall {
        srId: sr_id,
        keys: vec!["merchant".into()],
        values: vec![Default::default()],
    };
    let inner = Bytes::from(call.abi_encode());

    let result = env
        .actor
        .submit_tx_with_envelope(SPENDING_RECORD, inner, |mut bytes| {
            // Overwrite the BE-encoded submitted_block at [164..172)
            // with the value zero — guaranteed to be far older than
            // any reasonable validity window.
            for i in 164..172 {
                bytes[i] = 0;
            }
            tracing::info!(
                target: "pso_e2e::scenario",
                scenario = "S015",
                step = "tamper",
                submitted_block = 0u64,
                "forced submitted_block to 0"
            );
            bytes
        })
        .await;

    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S015", "actor pool refused stale envelope");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S015: expected PoolRejection on stale submitted_block, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S015: expected pool rejection but actor admitted tx {:?}",
            tx
        )),
    }
}
