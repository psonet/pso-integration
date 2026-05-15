//! S032 — actor RPC accepts an envelope whose VDF proof was
//! computed under the **previous** epoch's `T`, after the chain
//! has rolled the epoch forward.
//!
//! Pool validation logic (`pso-chain::pool::users::validate_user_tx`):
//!
//! ```text
//! let verified = MinRootVdf::verify(input, output, proof, current_T)
//!     || (previous_T != current_T
//!         && MinRootVdf::verify(input, output, proof, previous_T));
//! ```
//!
//! Wallets compute proofs against the difficulty visible at compute
//! time. If the chain transitions to a new epoch (and therefore a
//! new `T`) between the wallet's view and the tx's pool arrival,
//! the proof is still accepted under the previous-T fallback.
//! Without this fallback, every epoch-boundary submission would
//! be rejected and the wallet would have to recompute.
//!
//! Setup:
//! 1. Read `current_t` (== `T_BASE` at genesis: `previous == current`).
//! 2. Invoke `env.advance_epoch(current_t * 2)` — chain rolls
//!    `previous = current_t`, `current = 2 * current_t`.
//! 3. Compute an envelope with `T = current_t` (the OLD value, now
//!    stored as `previous`).
//! 4. Submit — pool tries the new `current` (fails), falls back to
//!    `previous`, accepts.

use crate::data::random_id;
use crate::{Scenario, TestEnv};
use alloy::primitives::Bytes;
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use pso_l2_client::abi::{ISpendingRecord, SPENDING_RECORD};

pub struct S032;

#[async_trait]
impl Scenario for S032 {
    fn id(&self) -> &'static str {
        "S032"
    }
    fn description(&self) -> &'static str {
        "actor RPC accepts envelope with VDF computed at the previous epoch's T after rollover"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let old_t = env
        .new_actor_as_sra_zero()?
        .fetch_difficulty()
        .await
        .map_err(|e| eyre::eyre!("S032: fetch_difficulty: {e}"))?;

    let new_t = old_t.saturating_mul(2);
    let (current, previous, epoch_start_block) = env
        .advance_epoch(new_t)
        .await
        .map_err(|e| eyre::eyre!("S032: advance_epoch({new_t}): {e}"))?;
    tracing::info!(
        scenario = "S032",
        old_t,
        new_current = current,
        new_previous = previous,
        epoch_start_block,
        "epoch rolled — chain should now accept proofs computed at the previous T",
    );

    if current != new_t || previous != old_t {
        return Err(eyre::eyre!(
            "S032: advance_epoch sanity: expected current={new_t} previous={old_t}, \
             got current={current} previous={previous}",
        ));
    }

    let sr_id = random_id();
    let call = ISpendingRecord::submitCall {
        srId: sr_id,
        keys: vec!["merchant".into()],
        values: vec![Default::default()],
    };
    let inner = Bytes::from(call.abi_encode());

    // Compute at `old_t`, which is now the chain's `previous` slot —
    // pool tries current (fails) then falls back to previous (accepts).
    let tx_hash = env
        .new_actor_as_sra_zero()?
        .submit_tx_with_difficulty(SPENDING_RECORD, inner, Some(old_t), |env_bytes| env_bytes)
        .await
        .map_err(|e| {
            eyre::eyre!("S032: expected previous-T fallback acceptance, got {e}")
        })?;

    tracing::info!(
        scenario = "S032",
        tx_hash = %tx_hash,
        "actor pool accepted previous-T envelope after rollover",
    );
    Ok(())
}
