//! S054 — replaying a nullifier through the actor RPC is rejected.
//!
//! The envelope's 32-byte nullifier ([`POW_NULLIFIER_RANGE`]) is the lane's
//! replay-protection cookie: the pool records every admitted one and refuses
//! any later envelope carrying it. Without that guard a captured envelope could
//! be re-broadcast indefinitely.
//!
//! The nullifier is deliberately NOT part of the anti-spam binding — that is
//! derived from `(signer, nonce, submitted_block, chain_id)` — so overwriting
//! the slot leaves the solution valid and the replay check is what decides.
//! That is the whole point of the test: it must reach the nullifier guard, not
//! trip the proof verifier on the way.
//!
//! Approach:
//! 1. Submit one envelope and capture the nullifier the builder rolled.
//! 2. Submit a second, independently built envelope with that nullifier forced
//!    into the slot.
//! 3. Expect a `PoolRejection` on the second.
//!
//! Whether the first transaction's inner call succeeds or reverts on-chain does
//! not matter; only the pool's record of the nullifier does.
use crate::clients::actor::ActorClientError;
use crate::clients::envelope::POW_NULLIFIER_RANGE;
use crate::data::USERS_LANE_PROBE_DEST;
use crate::{Scenario, TestEnv};
use alloy_primitives::Bytes;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

pub struct S054;

#[async_trait]
impl Scenario for S054 {
    fn id(&self) -> &'static str {
        "S054"
    }
    fn description(&self) -> &'static str {
        "actor RPC rejects an envelope replaying a previously-seen nullifier"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let first_nullifier: Arc<Mutex<Option<[u8; 32]>>> = Arc::new(Mutex::new(None));
    let captured = first_nullifier.clone();
    let first = env
        .new_actor_as_attester_zero()?
        .submit_tx_with_envelope(USERS_LANE_PROBE_DEST, Bytes::new(), move |bytes| {
            let mut n = [0u8; 32];
            n.copy_from_slice(&bytes[POW_NULLIFIER_RANGE]);
            *captured.lock().expect("nullifier capture") = Some(n);
            bytes
        })
        .await;

    // A pool rejection on the FIRST submission means the nullifier was never
    // recorded, so the replay below would prove nothing. Anything downstream of
    // admission is fine — an EVM revert still leaves the nullifier burned.
    match &first {
        Err(ActorClientError::PoolRejection(msg)) => {
            return Err(eyre::eyre!(
                "S054: first submission rejected by pool ({msg}); cannot test replay"
            ));
        }
        Err(other) => {
            tracing::info!(
                ?other,
                scenario = "S054",
                "first submission errored post-pool"
            );
        }
        Ok(tx) => {
            tracing::info!(?tx, scenario = "S054", "first submission admitted");
        }
    }

    let nullifier = first_nullifier
        .lock()
        .expect("nullifier capture")
        .ok_or_else(|| eyre::eyre!("S054: nullifier was never captured from the first envelope"))?;
    tracing::info!(
        scenario = "S054",
        step = "captured",
        nullifier = %hex::encode(nullifier),
        "first envelope nullifier",
    );

    let result = env
        .new_actor_as_attester_zero()?
        .submit_tx_with_envelope(USERS_LANE_PROBE_DEST, Bytes::new(), move |mut bytes| {
            bytes[POW_NULLIFIER_RANGE].copy_from_slice(&nullifier);
            tracing::info!(
                target: "pso_e2e::scenario",
                scenario = "S054",
                step = "tamper",
                "second envelope reuses the first nullifier"
            );
            bytes
        })
        .await;

    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S054", "actor pool refused the replayed nullifier");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S054: expected PoolRejection on the replayed nullifier, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S054: expected pool rejection but actor admitted replayed-nullifier tx {:?}",
            tx
        )),
    }
}
