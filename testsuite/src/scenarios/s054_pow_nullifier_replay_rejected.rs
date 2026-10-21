//! S054 — replaying a solution through the actor RPC is rejected.
//!
//! The anti-spam solution binds `(signer, nonce, submitted_block, chain_id)`.
//! The envelope's 32-byte nullifier slot ([`POW_NULLIFIER_RANGE`]) is not part
//! of that input, so the lane ignores the transmitted value and keys replay on
//! the nullifier it derives from `(signer, nonce, submitted_block)`. One
//! solution gives one nullifier, however the slot is filled.
//!
//! Approach:
//! 1. Submit one envelope and capture its exact wire bytes.
//! 2. Re-broadcast those bytes with a different value in the nullifier slot.
//!    The inner tx and the solution are unchanged, so they stay valid.
//! 3. Expect a `PoolRejection` naming `NullifierAlreadyUsed`.
//!
//! The reason is asserted, not just the rejection: the replay carries the same
//! nonce as the first tx, so a node that keyed on the transmitted nullifier
//! would still refuse it, as an underpriced replacement. Only the nullifier
//! reason shows the solution itself was refused.
//!
//! The replay goes out straight after the first admission, while the first tx
//! is still pending. Once it is mined, the inner nonce check refuses the replay
//! as "nonce too low" before the lane runs, and the scenario says so.
use crate::clients::actor::ActorClientError;
use crate::clients::envelope::POW_NULLIFIER_RANGE;
use crate::data::USERS_LANE_PROBE_DEST;
use crate::{Scenario, TestEnv};
use alloy_primitives::Bytes;
use async_trait::async_trait;
use serde_json::json;
use std::sync::{Arc, Mutex};

pub struct S054;

#[async_trait]
impl Scenario for S054 {
    fn id(&self) -> &'static str {
        "S054"
    }
    fn description(&self) -> &'static str {
        "actor RPC rejects a replayed solution carrying a new nullifier"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let actor = env.new_actor_as_attester_zero()?;

    let first_wire: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let captured = first_wire.clone();
    let first = actor
        .submit_tx_with_envelope(USERS_LANE_PROBE_DEST, Bytes::new(), move |bytes| {
            *captured.lock().expect("wire capture") = Some(bytes.clone());
            bytes
        })
        .await;

    // The first envelope must be admitted, or its nullifier was never recorded
    // and the replay below would prove nothing.
    let first_tx = first.map_err(|e| {
        eyre::eyre!("S054: first submission was not admitted ({e}); cannot test replay")
    })?;
    tracing::info!(?first_tx, scenario = "S054", "first submission admitted");

    let mut replay = first_wire
        .lock()
        .expect("wire capture")
        .take()
        .ok_or_else(|| {
            eyre::eyre!("S054: wire bytes were never captured from the first envelope")
        })?;
    for b in &mut replay[POW_NULLIFIER_RANGE] {
        *b = !*b;
    }
    tracing::info!(
        scenario = "S054",
        step = "tamper",
        nullifier = %hex::encode(&replay[POW_NULLIFIER_RANGE]),
        "replay carries the first solution with a new nullifier"
    );

    let result = actor
        .raw_json_rpc(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(&replay))]),
        )
        .await;

    match result {
        Err(ActorClientError::PoolRejection(msg)) if msg.contains("NullifierAlreadyUsed") => {
            tracing::info!(%msg, scenario = "S054", "actor pool refused the replayed solution");
            Ok(())
        }
        Err(other) if other.to_string().contains("nonce too low") => Err(eyre::eyre!(
            "S054: first tx {first_tx:?} was mined before the replay reached the lane ({other}); \
             the nullifier guard was not exercised"
        )),
        Err(other) => Err(eyre::eyre!(
            "S054: expected a NullifierAlreadyUsed rejection on the replay, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S054: expected pool rejection but actor admitted the replayed solution: {tx}"
        )),
    }
}
