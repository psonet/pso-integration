//! S025 — `SpendingRecord.submit` rejects metadata with mismatched
//! key / value array lengths.
//!
//! `_validateMetadata` (in `SpendingRecord.sol`) asserts
//! `keys.length == values.length`; anything else reverts with
//! `InvalidMetadata(reason)`. The reason string is a single
//! human-readable phrase the contract picks per-failure path; we
//! don't pin its exact wording — only the selector + that *some*
//! reason came through.

use alloy::primitives::FixedBytes;
use async_trait::async_trait;

use crate::clients::sra::into_pso_error;
use crate::data::random_id;
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S025;

#[async_trait]
impl Scenario for S025 {
    fn id(&self) -> &'static str {
        "S025"
    }
    fn description(&self) -> &'static str {
        "SR.submit with mismatched key/value lengths reverts InvalidMetadata"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let sr_id = random_id();
    // 2 keys, 1 value — the length-mismatch guard fires.
    let err = env
        .sra
        .register_spending_record(
            sr_id,
            vec!["merchant".into(), "amount".into()],
            vec![FixedBytes::from([0xa1u8; 32])],
        )
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S025: expected revert on metadata mismatch, got success"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::InvalidMetadata(reason) => {
            tracing::info!(scenario = "S025", reason = %reason, "InvalidMetadata reason captured");
            Ok(())
        }
        other => Err(eyre::eyre!("S025: expected InvalidMetadata, got {other}")),
    }
}
