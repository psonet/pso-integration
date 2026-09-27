//! S055 — actor RPC rejects an envelope whose `submitted_block` is too old.
//!
//! The lane accepts a proof only while `head - submitted_block` stays inside
//! `PSO_PROOF_MAX_AGE`; older is a stale or hoarded proof.
//!
//! The envelope is built HONESTLY against the old block rather than by
//! overwriting the `submitted_block` bytes, and that distinction is the test.
//! `submitted_block` feeds the derived binding, so a tampered byte changes the
//! input the node solves for and the solution stops verifying — and because
//! admission runs the proof check BEFORE the freshness window, a tampered
//! envelope is refused as a bad solution and never reaches the check this
//! scenario is about. Pinning the block instead keeps the solution genuinely
//! valid for the age it claims, so the window is the only thing left to reject
//! it.
//!
//! S043 is the other half of the same boundary: an envelope aged a few blocks,
//! still inside the window, must be ADMITTED.
use crate::clients::actor::ActorClientError;
use crate::data::USERS_LANE_PROBE_DEST;
use crate::{Scenario, TestEnv};
use alloy_primitives::Bytes;
use async_trait::async_trait;

pub struct S055;

/// Age to claim, in blocks. Far outside any plausible `PSO_PROOF_MAX_AGE`
/// (the default is 32) without depending on its configured value.
const STALE_AGE: u64 = 10_000;

#[async_trait]
impl Scenario for S055 {
    fn id(&self) -> &'static str {
        "S055"
    }
    fn description(&self) -> &'static str {
        "actor RPC rejects an envelope whose submitted_block is outside the proof window"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let actor = env.new_actor_as_attester_zero()?;
    let head = actor.block_number().await?;

    // The claimed age has to actually exceed the window, so the chain must have
    // produced enough blocks for `head - pinned` to be out of range. Fail with
    // the reason rather than asserting on a chain that is simply too young.
    eyre::ensure!(
        head > 64,
        "S055: chain at head {head} is too young to age a proof out of the window"
    );
    let pinned = head.saturating_sub(STALE_AGE);
    tracing::info!(
        scenario = "S055",
        head,
        pinned,
        age = head - pinned,
        "building a valid proof against an out-of-window block"
    );

    let result = actor
        .submit_tx_pinned(
            USERS_LANE_PROBE_DEST,
            Bytes::new(),
            None,
            Some(pinned),
            |e| e,
        )
        .await;

    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S055", "actor pool refused the stale envelope");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S055: expected PoolRejection on an out-of-window submitted_block, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S055: expected pool rejection but actor admitted stale tx {:?}",
            tx
        )),
    }
}
