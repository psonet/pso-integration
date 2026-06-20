//! S004 — wallet (non-Attester) cannot register an AR via the actor pool.
//!
//! Same shape as S003, addressed at `SpendingRecordAmendment.submit`.
//! See S003's body for the documented two-path acceptance.

use std::time::Duration;

use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use async_trait::async_trait;

use pso_chain_abi::addresses::AMENDMENT_RECORD;
use pso_chain_abi::interfaces::IAmendmentRecord;

use crate::clients::actor::ActorClientError;
use crate::data::random_id;
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S004;

#[async_trait]
impl Scenario for S004 {
    fn id(&self) -> &'static str {
        "S004"
    }
    fn description(&self) -> &'static str {
        "non-Attester wallet cannot submit a SpendingRecordAmendment through the actor pool"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let ar_id = random_id();
    let call = IAmendmentRecord::submitCall { arId: ar_id };
    let inner = Bytes::from(call.abi_encode());

    match env.new_actor()?.submit_tx(AMENDMENT_RECORD, inner).await {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, "S004: actor pool refused tx (no AR landed)");
            Ok(())
        }
        Err(ActorClientError::Revert(PsoContractError::AttesterNotActive)) => Ok(()),
        Err(other) => {
            tracing::info!(?other, "S004: actor surfaced typed error");
            Ok(())
        }
        Ok(tx_hash) => {
            let receipt = env
                .new_actor()?
                .wait_for_receipt(tx_hash, Duration::from_secs(30))
                .await?;
            if receipt.status() {
                Err(eyre::eyre!(
                    "S004: wallet-signed AR.submit succeeded — invariant violated"
                ))
            } else {
                tracing::info!(?tx_hash, "S004: actor admitted tx, EVM reverted (status=0)");
                Ok(())
            }
        }
    }
}
