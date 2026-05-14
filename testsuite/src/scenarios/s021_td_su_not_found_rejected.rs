//! S021 — `TributeDraft.submit` rejects a `suIds` array whose first
//! entry doesn't correspond to a registered SU.
//!
//! `_collectSuTotals` reads `spendingUnit.getData(suIds[0])` and
//! checks `submittedBy == address(0)`; default-zero on an unset
//! slot means the SU was never minted. The contract reverts with
//! `NotFound(suIds[0])`.
//!
//! No SU minting needed for this case — a phantom random id IS the
//! test surface. We do supply a plausible-looking `tdId` /
//! `derivedOwner` so the early `EmptyArray` / `AlreadyExists`
//! checks pass.

use alloy::primitives::{Bytes, FixedBytes};
use async_trait::async_trait;

use pso_l2_client::abi::{ITributeDraft, TRIBUTE_DRAFT};

use crate::clients::sra::into_pso_error;
use crate::data::random_id;
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S021;

#[async_trait]
impl Scenario for S021 {
    fn id(&self) -> &'static str {
        "S021"
    }
    fn description(&self) -> &'static str {
        "TD.submit with non-existent suId reverts NotFound"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let phantom_su = random_id();
    let provider = env.sra_zero.inner().write_provider()?;
    let td = ITributeDraft::new(TRIBUTE_DRAFT, provider);

    let err = td
        .submit(
            random_id(),
            FixedBytes::from([0u8; 32]),
            vec![phantom_su],
            Bytes::new(),
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S021: expected revert on phantom suId, got success"))?;

    let typed = into_pso_error(pso_l2_client::L2ClientError::Contract(format!("{err}")));
    match &typed {
        PsoContractError::NotFound(id) => {
            if *id != phantom_su {
                return Err(eyre::eyre!(
                    "S021: NotFound id mismatch: got {id}, expected {phantom_su}"
                ));
            }
            Ok(())
        }
        other => Err(eyre::eyre!("S021: expected NotFound(_), got {other}")),
    }
}
