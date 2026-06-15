//! S031 — actor RPC rejects an envelope whose VDF proof was
//! computed at a `T` outside the chain's accepted window.
//!
//! Pool validation logic (`pso-chain::pool::users::validate_user_tx`):
//!
//! ```text
//! let verified = MinRootVdf::verify(input, output, proof, current_T)
//!     || (previous_T != current_T
//!         && MinRootVdf::verify(input, output, proof, previous_T));
//! ```
//!
//! So the chain accepts iff the proof verifies under EITHER the
//! current epoch's `T` OR the previous epoch's `T`. Anything else
//! — including a deliberately higher `T` chosen by the wallet
//! ("more work than necessary" is not a shortcut) — gets bounced
//! as `PoolRejection`. That's by-design; the wallet can't pre-pay
//! difficulty against arbitrary future epochs.
//!
//! We compute the envelope at `current_difficulty * 3` (way past
//! the current ∪ previous window) and assert rejection.
use crate::clients::actor::ActorClientError;
use crate::data::random_id;
use crate::{Scenario, TestEnv};
use alloy::primitives::Bytes;
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use pso_l2_client::abi::{ISpendingRecord, SPENDING_RECORD};
pub struct S031;
#[async_trait]
impl Scenario for S031 {
    fn id(&self) -> &'static str {
        "S031"
    }
    fn description(&self) -> &'static str {
        "actor RPC rejects envelope with VDF computed at T outside current ∪ previous"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}
async fn run(env: &TestEnv) -> eyre::Result<()> {
    let current_t = env
        .new_actor_as_sra_zero()?
        .fetch_difficulty()
        .await
        .map_err(|e| eyre::eyre!("S031: fetch_difficulty: {e}"))?;
    let wrong_t = current_t.saturating_mul(3);
    tracing::info!(
        scenario = "S031",
        current_t,
        wrong_t,
        "submitting envelope with T outside the current ∪ previous window",
    );
    let sr_id = random_id();
    let call = ISpendingRecord::submitCall { srId: sr_id };
    let inner = Bytes::from(call.abi_encode());
    let result = env
        .new_actor_as_sra_zero()?
        .submit_tx_with_difficulty(SPENDING_RECORD, inner, Some(wrong_t), |env_bytes| env_bytes)
        .await;
    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S031", "actor pool refused wrong-difficulty envelope");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S031: expected PoolRejection on wrong T, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S031: expected pool rejection but actor admitted tx {:?}",
            tx
        )),
    }
}
