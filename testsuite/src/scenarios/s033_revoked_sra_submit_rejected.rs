//! S033 — a revoked SRA's `SpendingRecord.submit` reverts with
//! `SRANotActive`.
//!
//! Lifecycle the scenario exercises end-to-end:
//!
//! 1. Spawn a fresh SRA via [`TestEnv::new_sra`] (admin
//!    `register_sra` + wait on `isActive`).
//! 2. Confirm it can submit an SR (sanity check that the address
//!    really is live in the registry).
//! 3. Admin `revoke_sra(addr)`.
//! 4. The same SRA attempts a second SR submission. The
//!    `onlyActiveSRA` modifier reads `isActive(addr) == false`
//!    post-revoke and reverts `SRANotActive`.
//!
//! Bookends the S030 invariant ("a never-registered SRA can't
//! submit") with the temporal axis ("a previously-registered SRA
//! who was revoked can't submit either").

use std::time::Duration;

use alloy::primitives::FixedBytes;
use async_trait::async_trait;

use pso_l2_client::PsoContractError;

use crate::clients::sra::into_pso_error;
use crate::data::random_id;
use crate::{Scenario, TestEnv};

pub struct S033;

#[async_trait]
impl Scenario for S033 {
    fn id(&self) -> &'static str {
        "S033"
    }
    fn description(&self) -> &'static str {
        "revoked SRA's SR.submit reverts SRANotActive"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let sra = env.new_sra().await?;
    let addr = sra.address();
    tracing::info!(scenario = "S033", %addr, "spawned fresh SRA");

    // Sanity check: a freshly-registered SRA must succeed at one
    // SR submission before we revoke. Otherwise a failure on step
    // 4 wouldn't necessarily isolate the revoke.
    let sr_id_pre = random_id();
    let tx = sra
        .register_spending_record(
            sr_id_pre,
            vec!["merchant".into()],
            vec![FixedBytes::from([0xa1u8; 32])],
        )
        .await?;
    sra.wait_for_tx_success(tx, Duration::from_secs(30)).await?;
    tracing::info!(scenario = "S033", "pre-revoke SR submission landed");

    env.admin
        .revoke_sra(addr)
        .await
        .map_err(|e| eyre::eyre!("revoke_sra: {e}"))?;
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

    // Now the same SRA attempts a second SR. Same shape as the
    // pre-revoke one — only the registry-side state changed.
    let sr_id_post = random_id();
    let err = sra
        .register_spending_record(
            sr_id_post,
            vec!["merchant".into()],
            vec![FixedBytes::from([0xb2u8; 32])],
        )
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S033: expected SRANotActive after revoke, got success"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::SRANotActive => Ok(()),
        other => Err(eyre::eyre!("S033: expected SRANotActive, got {other}")),
    }
}
