//! S049 — a `0x77` envelope with a corrupted solution is refused.
//!
//! The counterpart to S048, and the one that makes it mean something. A node
//! that admitted `0x77` unconditionally — never checking the work — would pass
//! S048 perfectly while providing no anti-spam at all. That is precisely the
//! failure SR-43 was about: the old scheme *verified*, it just verified
//! something forgeable.
//!
//! Flipping one bit of the nonce is enough. The digest is
//! `SHA-256(input ‖ nonce)` against a 256-bit target, so any change to the
//! nonce re-rolls the hash and it will not clear the target except with
//! probability `1/T`.
//!
//! This replaces S016/S017 for the new format. Those tamper with the MinRoot
//! output and proof respectively — fields `0x77` does not have — so they have
//! no direct analogue and collapse into this single "the work was wrong" case.
use crate::clients::actor::ActorClientError;
use crate::data::USERS_LANE_PROBE_DEST;
use crate::{Scenario, TestEnv};
use alloy_primitives::Bytes;
use async_trait::async_trait;

pub struct S049;

#[async_trait]
impl Scenario for S049 {
    fn id(&self) -> &'static str {
        "S049"
    }
    fn description(&self) -> &'static str {
        "users RPC rejects a 0x77 envelope whose PoW solution is corrupted"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let inner = Bytes::new();

    let result = env
        .new_actor_as_attester_zero()?
        .submit_pow_tx(USERS_LANE_PROBE_DEST, inner, |mut bytes| {
            // Flip the low bit of the last solution byte. The rest of the
            // envelope stays valid, so the ONLY thing wrong is the work —
            // which is what this scenario is about.
            let last = crate::clients::envelope::POW_SOLUTION_RANGE.end - 1;
            bytes[last] ^= 0x01;
            tracing::info!(
                target: "pso_e2e::scenario",
                scenario = "S049",
                step = "tamper",
                byte = last,
                "flipped one bit of the hashcash nonce"
            );
            bytes
        })
        .await;

    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S049", "pool refused the corrupted solution");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S049: expected PoolRejection on a corrupted solution, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S049: the pool ADMITTED a 0x77 envelope with invalid work (tx {tx:#x}) — \
             the anti-spam gate is not checking the solution at all"
        )),
    }
}
