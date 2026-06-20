//! S036 — `AttestersRegistry.setRotationCandidate` mutates the on-chain
//! record and `getRecord` reads back the new value.
//!
//! [`TestEnv::new_attester`] registers freshly-rolled Attesters as **non-rotation**
//! attesters with a zero consensus identity (they only need to be active to
//! submit). M3's `AttestersRegistry` rejects rotation candidacy without a
//! non-zero `consensusKey`, so the round-trip we exercise is: set a consensus
//! identity, flip rotation on (`false -> true`), and read it back — covering
//! both [`AdminClient::set_consensus_identity`] and
//! [`AdminClient::set_rotation_candidate`] at the sequencer-rotation seam.
//!
//! The dummy `consensusKey` has no live DKG node, so the scenario REVERTS the
//! rotation candidacy once the round-trip is observed: the node's epoch manager
//! reshares the threshold committee toward every rotation candidate each epoch
//! boundary, and a candidate with no live participant makes the reshare fail
//! repeatedly (stalling block production, eventually wedging on restart).
//! Restoring the registry keeps the single-node devnet healthy for later
//! scenarios.

use std::time::Duration;

use alloy_primitives::{B256, U256};
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
    let attester = env.new_attester().await?;
    let addr = attester.address();

    // new_attester registers non-rotation; confirm the baseline.
    let initial = env.admin.get_record(addr).await?;
    if initial.isRotationCandidate {
        return Err(eyre::eyre!(
            "S036: new_attester() unexpectedly bootstrapped with isRotationCandidate=true"
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
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "S036: setRotationCandidate didn't read back within 30s"
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // CLEANUP — revert the rotation candidacy. This is consensus-critical
    // shared state: the node's epoch manager reads `rotationCandidatesSorted()`
    // at every epoch boundary and tries to reshare the threshold committee to
    // include each candidate. This Attester's `consensusKey` is the dummy `0x11..11`
    // with no live DKG node behind it, so leaving it a candidate makes every
    // subsequent reshare fail (`UnknownDealer`), stalling block production at
    // each boundary and eventually wedging the committee. The round-trip we set
    // out to verify is already observed above; restore the registry so the
    // single-node devnet's rotation set stays clean for later scenarios.
    env.admin
        .set_rotation_candidate(addr, false)
        .await
        .map_err(|e| eyre::eyre!("set_rotation_candidate(false) cleanup: {e}"))?;

    // Generous deadline: if an epoch boundary snapshotted the candidate while it
    // was active, the node is mid-reshare toward the dummy key — a ceremony that
    // times out (RESHARE_TIMEOUT=20s × RESHARE_MAX_ATTEMPTS=2 = ~40s) before
    // falling back to the previous committee, slowing block production until it
    // does. The cleanup tx still gets mined in those (slower) blocks; we just
    // have to wait past the stall. Landing it ends the degradation: the next
    // boundary sees n=1 again and stops resharing.
    let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        if !env.admin.get_record(addr).await?.isRotationCandidate {
            tracing::info!(scenario = "S036", "rotation-candidate cleanup confirmed");
            return Ok(());
        }
        if std::time::Instant::now() >= cleanup_deadline {
            return Err(eyre::eyre!(
                "S036: rotation-candidate cleanup didn't read back false within 120s"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
