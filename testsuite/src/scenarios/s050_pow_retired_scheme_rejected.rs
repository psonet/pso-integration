//! S050 — a `0x77` envelope tagged with the RETIRED MinRoot scheme is refused.
//!
//! The scheme tag is on the wire so two schemes can be accepted during a
//! rollout. That flexibility is also a hole if the node trusts the tag: a
//! client could keep the new envelope shape while asking to be verified under
//! the old, forgeable construction — SR-43 through the front door.
//!
//! `PowScheme::MinRoot` therefore decodes (so a legacy envelope can be given a
//! truthful rejection rather than a shrug) but never VERIFIES. This asserts the
//! node agrees, which neither S048 nor S049 covers: both use the hashcash tag,
//! so a node that verified whatever scheme it was told would pass them.
//!
//! Distinct from the `accept_legacy_vdf` window, which governs the `0x76` wire
//! format. This is the `0x77` format carrying the retired tag, and no operator
//! setting should make it verifiable.
use crate::clients::actor::ActorClientError;
use crate::data::USERS_LANE_PROBE_DEST;
use crate::{Scenario, TestEnv};
use alloy_primitives::Bytes;
use async_trait::async_trait;
use pso_antispam::PowScheme;

pub struct S050;

#[async_trait]
impl Scenario for S050 {
    fn id(&self) -> &'static str {
        "S050"
    }
    fn description(&self) -> &'static str {
        "users RPC rejects a 0x77 envelope tagged with the retired MinRoot scheme"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let inner = Bytes::new();

    // The builder cannot solve a retired scheme, so it emits a correctly
    // shaped, correctly tagged, all-zero solution — which is exactly what an
    // attacker trying this would have.
    let result = env
        .new_actor_as_attester_zero()?
        .submit_pow_tx_with_scheme(PowScheme::MinRoot, USERS_LANE_PROBE_DEST, inner, |bytes| {
            bytes
        })
        .await;

    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S050", "pool refused the retired scheme tag");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S050: expected PoolRejection for the retired scheme tag, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S050: the pool ADMITTED a 0x77 envelope tagged MinRoot (tx {tx:#x}) — \
             a client can opt back into the forgeable scheme by asking for it"
        )),
    }
}
