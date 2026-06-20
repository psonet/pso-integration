//! S033 — a revoked Attester's `SpendingRecord.submit` reverts with
//! `AttesterNotActive`.
//!
//! Lifecycle the scenario exercises end-to-end:
//!
//! 1. Spawn a fresh Attester via [`TestEnv::new_attester`] (admin
//!    `register_attester` + wait on `isActive`).
//! 2. Confirm it can submit an SR (sanity check that the address
//!    really is live in the registry).
//! 3. Admin `revoke_attester(addr)`.
//! 4. The same Attester attempts a second SR submission. The
//!    `onlyActiveAttester` modifier reads `isActive(addr) == false`
//!    post-revoke and reverts `AttesterNotActive`.
//!
//! Bookends the S030 invariant ("a never-registered Attester can't
//! submit") with the temporal axis ("a previously-registered Attester
//! who was revoked can't submit either").

use std::time::Duration;

use async_trait::async_trait;

use crate::clients::attester::into_pso_error;
use crate::data::random_id;
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S033;

#[async_trait]
impl Scenario for S033 {
    fn id(&self) -> &'static str {
        "S033"
    }
    fn description(&self) -> &'static str {
        "revoked Attester's SR.submit reverts AttesterNotActive"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let attester = env.new_attester().await?;
    let addr = attester.address();
    tracing::info!(scenario = "S033", %addr, "spawned fresh Attester");

    // Sanity check: a freshly-registered Attester must succeed at one
    // SR submission before we revoke. Otherwise a failure on step
    // 4 wouldn't necessarily isolate the revoke.
    let sr_id_pre = random_id();
    let tx = attester.register_spending_record(sr_id_pre).await?;
    attester
        .wait_for_tx_success(tx, Duration::from_secs(30))
        .await?;
    tracing::info!(scenario = "S033", "pre-revoke SR submission landed");

    env.admin
        .revoke_attester(addr)
        .await
        .map_err(|e| eyre::eyre!("revoke_attester: {e}"))?;
    // Read-back: the active bit must flip before we try the next
    // submission, otherwise the revoke tx hasn't landed yet.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while env.admin.is_active(addr).await? {
        if std::time::Instant::now() >= deadline {
            return Err(eyre::eyre!("S033: revoke didn't take effect within 30s"));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    tracing::info!(scenario = "S033", "revoke observed on chain");

    // Now the same Attester attempts a second SR. Same shape as the
    // pre-revoke one — only the registry-side state changed.
    let sr_id_post = random_id();
    let err = attester
        .register_spending_record(sr_id_post)
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S033: expected AttesterNotActive after revoke, got success"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::AttesterNotActive => Ok(()),
        other => Err(eyre::eyre!("S033: expected AttesterNotActive, got {other}")),
    }
}
