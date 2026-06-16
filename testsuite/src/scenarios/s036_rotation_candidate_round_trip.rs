//! S036 — `AttestersRegistry.setRotationCandidate` mutates the on-chain
//! record and `getRecord` reads back the new value.
//!
//! [`TestEnv::new_sra`] registers freshly-rolled SRAs as **non-rotation**
//! attesters with a zero consensus identity (they only need to be active to
//! submit). M3's `AttestersRegistry` rejects rotation candidacy without a
//! non-zero `consensusKey`, so the round-trip we exercise is: set a consensus
//! identity, flip rotation on (`false -> true`), and read it back — covering
//! both [`AdminClient::set_consensus_identity`] and
//! [`AdminClient::set_rotation_candidate`] at the sequencer-rotation seam.

use std::time::Duration;

use alloy::primitives::{B256, U256};
use async_trait::async_trait;

use crate::{Scenario, TestEnv};

pub struct S036;

#[async_trait]
impl Scenario for S036 {
    fn id(&self) -> &'static str {
        "S036"
    }
    fn description(&self) -> &'static str {
        "admin.set_rotation_candidate round-trips through getRecord"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let sra = env.new_sra().await?;
    let addr = sra.address();

    // new_sra registers non-rotation; confirm the baseline.
    let initial = env.admin.get_record(addr).await?;
    if initial.isRotationCandidate {
        return Err(eyre::eyre!(
            "S036: new_sra() unexpectedly bootstrapped with isRotationCandidate=true"
        ));
    }

    // M3 invariant: a rotation candidate must carry a non-zero consensusKey.
    // Set a dummy identity first, then flip rotation on — but the identity
    // tx must LAND before setRotationCandidate runs (the contract reads the
    // stored key), so poll getRecord until the key is observed.
    let dummy_key = B256::repeat_byte(0x11);
    env.admin
        .set_consensus_identity(addr, dummy_key, U256::ZERO)
        .await
        .map_err(|e| eyre::eyre!("set_consensus_identity: {e}"))?;

    let key_deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if env.admin.get_record(addr).await?.consensusKey == dummy_key {
            break;
        }
        if std::time::Instant::now() >= key_deadline {
            return Err(eyre::eyre!("S036: consensusKey didn't land within 30s"));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    env.admin
        .set_rotation_candidate(addr, true)
        .await
        .map_err(|e| eyre::eyre!("set_rotation_candidate: {e}"))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let rec = env.admin.get_record(addr).await?;
        if rec.isRotationCandidate {
            if !rec.active {
                return Err(eyre::eyre!(
                    "S036: setRotationCandidate flipped active — should be no-op for active state"
                ));
            }
            tracing::info!(
                scenario = "S036",
                "set_rotation_candidate(true) round-trip observed"
            );
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "S036: setRotationCandidate didn't read back within 30s"
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
