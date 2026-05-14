//! S025 — `SpendingRecord.submit` rejects metadata with mismatched
//! key / value array lengths.
//!
//! `_validateMetadata` (in `SpendingRecord.sol`) asserts
//! `keys.length == values.length`; anything else reverts with
//! `InvalidMetadata(reason)`. The reason string is a single
//! human-readable phrase the contract picks per-failure path; we
//! don't pin its exact wording — only the selector + that *some*
//! reason came through.
//!
//! `pso-l2-client::sra::register_spending_record` validates length
//! locally before broadcasting, so we bypass that wrapper and call
//! the `SpendingRecord.submit(...)` contract method directly via
//! alloy. The raw EVM call ships malformed inputs through to the
//! on-chain guard.

use alloy::primitives::FixedBytes;
use async_trait::async_trait;

use pso_l2_client::abi::{ISpendingRecord, SPENDING_RECORD};
use pso_l2_client::{into_pso_error, L2ClientError};

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
    let provider = env.sra_zero.inner().write_provider()?;
    let sr = ISpendingRecord::new(SPENDING_RECORD, provider);

    let sr_id = random_id();
    let err = sr
        .submit(
            sr_id,
            // 2 keys, 1 value — the length-mismatch guard fires.
            vec!["merchant".into(), "amount".into()],
            vec![FixedBytes::from([0xa1u8; 32])],
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S025: expected revert on metadata mismatch, got success"))?;

    let typed = into_pso_error(L2ClientError::Contract(format!("{err}")));
    match &typed {
        PsoContractError::InvalidMetadata(reason) => {
            tracing::info!(scenario = "S025", reason = %reason, "InvalidMetadata reason captured");
            Ok(())
        }
        other => Err(eyre::eyre!("S025: expected InvalidMetadata, got {other}")),
    }
}
