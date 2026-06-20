//! S035 — `AttestersRegistry.updateMask` mutates the on-chain record
//! and `getRecord` reads back the new value.
//!
//! Positive-side complement to S029 (admin sets `mask = 0` →
//! `InvalidMask`). Here we walk the happy path twice:
//!
//! 1. Spawn a fresh Attester via [`TestEnv::new_attester`] — bootstrapped
//!    with `mask = ATTESTER_PERMISSION_MASK` (0xF, SU/SR/AR/heartbeat;
//!    deliberately not ADMIN_MASK — see `env.rs`).
//! 2. Read the record back via `admin.get_record`. Assert
//!    `mask == ATTESTER_PERMISSION_MASK`, `active == true`.
//! 3. `admin.update_mask(addr, 0x03)` — shrink to SU+SR only so the
//!    changed bits are obvious.
//! 4. Re-read and assert `mask == 0x03`. `active` should still
//!    be true (updateMask doesn't touch the active flag).

use std::time::Duration;

use async_trait::async_trait;

use crate::env::ATTESTER_PERMISSION_MASK;
use crate::{Scenario, TestEnv};

pub struct S035;

#[async_trait]
impl Scenario for S035 {
    fn id(&self) -> &'static str {
        "S035"
    }
    fn description(&self) -> &'static str {
        "admin.update_mask round-trips through getRecord"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let attester = env.new_attester().await?;
    let addr = attester.address();
    tracing::info!(scenario = "S035", %addr, "spawned fresh Attester");

    let initial = env.admin.get_record(addr).await?;
    if initial.permissionMask != ATTESTER_PERMISSION_MASK {
        return Err(eyre::eyre!(
            "S035: expected initial mask 0x{ATTESTER_PERMISSION_MASK:08x}, got 0x{:08x}",
            initial.permissionMask
        ));
    }
    if !initial.active {
        return Err(eyre::eyre!(
            "S035: freshly-registered Attester is not active"
        ));
    }

    let new_mask: u32 = 0x03;
    env.admin
        .update_mask(addr, new_mask)
        .await
        .map_err(|e| eyre::eyre!("update_mask: {e}"))?;

    // Wait for read-back. updateMask is non-atomic with respect
    // to read RPC.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let rec = env.admin.get_record(addr).await?;
        if rec.permissionMask == new_mask {
            if !rec.active {
                return Err(eyre::eyre!(
                    "S035: updateMask flipped active flag — should be a no-op for active state"
                ));
            }
            tracing::info!(
                scenario = "S035",
                mask = format!("0x{new_mask:08x}"),
                "updateMask round-trip observed"
            );
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "S035: updateMask didn't read back within 30s; last seen 0x{:08x}",
                rec.permissionMask
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
