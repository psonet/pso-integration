//! S014 — replaying a nullifier through the actor RPC is rejected.
//!
//! The PSO envelope's 32-byte nullifier (bytes 4..36) is the chain's
//! replay-protection cookie. The pool validator records every
//! observed nullifier and rejects any subsequent envelope carrying
//! one that's already been admitted. Without that guard a captured
//! envelope could be re-broadcast indefinitely.
//!
//! Approach:
//! 1. Submit a first envelope via the standard
//!    [`ActorClient::submit_tx`] path; capture its bytes
//!    transparently by stealing the nullifier slot from a second,
//!    custom-built envelope.
//! 2. Submit a second envelope that reuses the first's nullifier.
//! 3. Expect a `PoolRejection` on the second submission.
//!
//! We don't care whether the first tx's INNER call eventually
//! succeeds or reverts on-chain — only the pool's view of
//! "nullifier already seen" matters.
use crate::clients::actor::ActorClientError;
use crate::data::random_id;
use crate::{Scenario, TestEnv};
use alloy::primitives::Bytes;
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use pso_l2_client::abi::{ISpendingRecord, SPENDING_RECORD};
use std::sync::{Arc, Mutex};
pub struct S014;
#[async_trait]
impl Scenario for S014 {
    fn id(&self) -> &'static str {
        "S014"
    }
    fn description(&self) -> &'static str {
        "actor RPC rejects envelope replaying a previously-seen nullifier"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}
async fn run(env: &TestEnv) -> eyre::Result<()> {
    // First submission: capture the nullifier the canonical builder
    // rolled (bytes [4..36) of the envelope).
    let first_nullifier: Arc<Mutex<Option<[u8; 32]>>> = Arc::new(Mutex::new(None));
    let captured = first_nullifier.clone();
    let sr_id_a = random_id();
    let call_a = ISpendingRecord::submitCall { srId: sr_id_a };
    let inner_a = Bytes::from(call_a.abi_encode());
    let first = env
        .new_actor_as_sra_zero()?
        .submit_tx_with_envelope(SPENDING_RECORD, inner_a, move |bytes| {
            let mut n = [0u8; 32];
            n.copy_from_slice(&bytes[4..36]);
            *captured.lock().expect("nullifier capture") = Some(n);
            bytes
        })
        .await;
    // Accept either pool admission or an EVM-level revert downstream
    // — the only thing we care about is the pool recording the
    // nullifier. PoolRejection on the FIRST submission means the
    // chain rejected before the nullifier was recorded, which would
    // invalidate the replay test.
    match &first {
        Err(ActorClientError::PoolRejection(msg)) => {
            return Err(eyre::eyre!(
                "S014: first submission rejected by pool ({msg}); cannot test replay"
            ));
        }
        Err(other) => {
            tracing::info!(
                ?other,
                scenario = "S014",
                "first submission errored post-pool"
            );
        }
        Ok(tx) => {
            tracing::info!(?tx, scenario = "S014", "first submission admitted");
        }
    }
    let nullifier = first_nullifier
        .lock()
        .expect("nullifier capture")
        .ok_or_else(|| eyre::eyre!("S014: nullifier was never captured from first envelope"))?;
    tracing::info!(
        scenario = "S014",
        step = "captured",
        nullifier = %hex::encode(nullifier),
        "first envelope nullifier",
    );
    // Second submission: build a fresh envelope (new VDF / fresh
    // submitted_block / fresh inner) but force the nullifier slot to
    // the captured value from the first.
    let sr_id_b = random_id();
    let call_b = ISpendingRecord::submitCall { srId: sr_id_b };
    let inner_b = Bytes::from(call_b.abi_encode());
    let result = env
        .new_actor_as_sra_zero()?
        .submit_tx_with_envelope(SPENDING_RECORD, inner_b, move |mut bytes| {
            bytes[4..36].copy_from_slice(&nullifier);
            tracing::info!(
                target: "pso_e2e::scenario",
                scenario = "S014",
                step = "tamper",
                "second envelope reuses first nullifier"
            );
            bytes
        })
        .await;
    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S014", "actor pool refused replayed nullifier");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S014: expected PoolRejection on replayed nullifier, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S014: expected pool rejection but actor admitted replayed-nullifier tx {:?}",
            tx
        )),
    }
}
