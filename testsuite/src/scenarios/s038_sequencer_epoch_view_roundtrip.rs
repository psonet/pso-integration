//! S038 — `SequencerEpoch` view-function round-trip.
//!
//! Read-only sanity check that the rotation contract is wired up at
//! its predeploy address and returns coherent values:
//!
//! 1. `EPOCH_LENGTH()` returns the documented constant (128).
//! 2. `TAKEOVER_DELAY()` returns the documented constant (16).
//! 3. `currentEpoch()` answers without revert.
//! 4. `leaderForEpoch(epoch, anchor)` returns a non-zero registered SRA
//!    (in the integration testsuite that's `sra_zero`, registered by
//!    [`crate::env::bootstrap_register_sra`]).
//! 5. `rankedLeadersForEpoch(epoch, anchor)` returns a non-empty list
//!    whose first element matches `leaderForEpoch`.
//!
//! This doesn't exercise leader rotation across epochs (that needs a
//! larger multi-SRA setup); it confirms the contract exists, returns
//! the right shape, and the rank-0 entry agrees between the two
//! query paths.

use alloy::primitives::{Address, FixedBytes};
use async_trait::async_trait;
use pso_l2_client::abi::{ISequencerEpoch, SEQUENCER_EPOCH};

use crate::{Scenario, TestEnv};

pub struct S038;

#[async_trait]
impl Scenario for S038 {
    fn id(&self) -> &'static str {
        "S038"
    }
    fn description(&self) -> &'static str {
        "SequencerEpoch view round-trip: constants, currentEpoch, leaderForEpoch, rankedLeadersForEpoch"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let provider = env.admin.inner().read_provider();
    let epoch = ISequencerEpoch::new(SEQUENCER_EPOCH, &provider);

    let epoch_length = epoch.EPOCH_LENGTH().call().await?;
    let takeover_delay = epoch.TAKEOVER_DELAY().call().await?;
    let current_epoch = epoch.currentEpoch().call().await?;
    tracing::info!(
        scenario = "S038",
        epoch_length,
        takeover_delay,
        current_epoch,
        "SequencerEpoch constants + currentEpoch readable",
    );

    if epoch_length != 128 {
        return Err(eyre::eyre!(
            "S038: EPOCH_LENGTH expected 128, got {epoch_length}"
        ));
    }
    if takeover_delay != 16 {
        return Err(eyre::eyre!(
            "S038: TAKEOVER_DELAY expected 16, got {takeover_delay}"
        ));
    }

    // Use a deterministic non-zero anchor so the leader selection is
    // reproducible across runs without depending on chain history.
    let anchor: FixedBytes<32> = FixedBytes::from([0xAB; 32]);

    let leader = epoch
        .leaderForEpoch(current_epoch, anchor)
        .call()
        .await?;
    if leader == Address::ZERO {
        return Err(eyre::eyre!(
            "S038: leaderForEpoch returned the zero address (no active SRAs?)"
        ));
    }

    let ranked = epoch
        .rankedLeadersForEpoch(current_epoch, anchor)
        .call()
        .await?;
    let first = ranked
        .first()
        .copied()
        .ok_or_else(|| eyre::eyre!("S038: rankedLeadersForEpoch returned an empty list"))?;
    if first != leader {
        return Err(eyre::eyre!(
            "S038: rank-0 mismatch: rankedLeadersForEpoch[0]={first}, leaderForEpoch={leader}"
        ));
    }

    tracing::info!(
        scenario = "S038",
        current_epoch,
        leader = %leader,
        ranked_len = ranked.len(),
        "leaderForEpoch + rankedLeadersForEpoch agree on rank-0",
    );
    Ok(())
}
