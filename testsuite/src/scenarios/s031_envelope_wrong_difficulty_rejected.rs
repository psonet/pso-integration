//! S031 — actor RPC rejects an envelope solved at too low a difficulty.
//!
//! Admission accepts iff the solution satisfies EITHER the current epoch's
//! difficulty or the previous epoch's:
//!
//! ```text
//! scheme.verify(input, solution, current)
//!     || (previous != current && scheme.verify(input, solution, previous))
//! ```
//!
//! The direction matters, and it is the opposite of what a sequential VDF would
//! give. Hashcash is a THRESHOLD: a solution carrying more leading zero bits
//! than required also satisfies any lower difficulty, so over-solving is
//! legitimate and admitting it is correct — a wallet that did extra work has not
//! cheated. Only UNDER-solving is a shortcut, so that is what this asserts.
//!
//! The chosen difficulty must sit below BOTH published values, or the solution
//! would satisfy whichever is lower and be admitted for a good reason.
use crate::clients::actor::ActorClientError;
use crate::data::USERS_LANE_PROBE_DEST;
use crate::{Scenario, TestEnv};
use alloy_primitives::Bytes;
use async_trait::async_trait;
pub struct S031;
#[async_trait]
impl Scenario for S031 {
    fn id(&self) -> &'static str {
        "S031"
    }
    fn description(&self) -> &'static str {
        "actor RPC rejects an envelope solved below both accepted difficulties"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}
async fn run(env: &TestEnv) -> eyre::Result<()> {
    let info = env
        .new_actor_as_attester_zero()?
        .fetch_vdf_info()
        .await
        .map_err(|e| eyre::eyre!("S031: fetch_vdf_info: {e}"))?;
    // Below BOTH accepted values, so neither arm of the check can pass it.
    let floor = info.current_difficulty.min(info.previous_difficulty);
    let wrong_t = (floor / 4).max(1);
    eyre::ensure!(
        wrong_t < floor,
        "S031: difficulty floor {floor} is too low to under-solve against"
    );
    tracing::info!(
        scenario = "S031",
        current_t = info.current_difficulty,
        previous_t = info.previous_difficulty,
        wrong_t,
        "submitting an envelope solved below both accepted difficulties",
    );
    let inner = Bytes::new();
    let result = env
        .new_actor_as_attester_zero()?
        .submit_tx_with_difficulty(USERS_LANE_PROBE_DEST, inner, Some(wrong_t), |env_bytes| {
            env_bytes
        })
        .await;
    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S031", "actor pool refused under-solved envelope");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S031: expected PoolRejection on an under-solved envelope, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S031: expected pool rejection but actor admitted tx {:?}",
            tx
        )),
    }
}
