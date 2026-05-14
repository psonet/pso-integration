//! S036 — `SRARegistry.setRotationCandidate` mutates the on-chain
//! record and `getRecord` reads back the new value.
//!
//! [`TestEnv::new_sra`] registers freshly-rolled SRAs with
//! `isRotationCandidate = true`, so the round-trip we exercise
//! is the *flip* (`true -> false`) rather than the initial set.
//! Symmetric coverage of [`AdminClient::set_rotation_candidate`]
//! at the sequencer-rotation seam.

use std::time::Duration;

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

    let initial = env.admin.get_record(addr).await?;
    if !initial.isRotationCandidate {
        return Err(eyre::eyre!(
            "S036: new_sra() didn't bootstrap with isRotationCandidate=true; saw false"
        ));
    }

    env.admin
        .set_rotation_candidate(addr, false)
        .await
        .map_err(|e| eyre::eyre!("set_rotation_candidate: {e}"))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let rec = env.admin.get_record(addr).await?;
        if !rec.isRotationCandidate {
            if !rec.active {
                return Err(eyre::eyre!(
                    "S036: setRotationCandidate flipped active — should be no-op for active state"
                ));
            }
            tracing::info!(
                scenario = "S036",
                "set_rotation_candidate(false) round-trip observed"
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
