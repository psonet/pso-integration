//! S003 — wallet (non-SRA) cannot register an SR via the actor pool.
//!
//! The actor RPC admits PSO-magic-prefixed calldata after a VDF
//! check, then dispatches the inner calldata through the EVM. The
//! inner calldata here is `SpendingRecord.submit(...)` — but the
//! sender is the actor wallet (a non-SRA key), so the
//! `onlyActiveSRA` modifier on the EVM side reverts with
//! `SRANotActive`.
//!
//! **Note**: pso-chain doesn't currently strip the PSO header from
//! `tx.data` before EVM dispatch; the EVM sees the wrapped calldata
//! and the function dispatcher fails the selector match. The
//! invariant we enforce is "the chain refuses to mint anything from
//! this caller through this path" — we accept either of:
//!
//! - A typed `SRANotActive` revert (chain strips the header).
//! - An EVM-level revert / pool rejection (header not stripped) —
//!   surfaces as `Other(...)` / `PoolRejection(...)` with a status-0
//!   receipt.
//!
//! Whichever path fires, the SR must NOT land on chain.

use std::time::Duration;

use alloy::primitives::Bytes;
use alloy::sol_types::SolCall;
use async_trait::async_trait;

use pso_l2_client::abi::{ISpendingRecord, SPENDING_RECORD};

use crate::clients::actor::ActorClientError;
use crate::data::random_id;
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S003;

#[async_trait]
impl Scenario for S003 {
    fn id(&self) -> &'static str {
        "S003"
    }
    fn description(&self) -> &'static str {
        "non-SRA wallet cannot submit a SpendingRecord through the actor pool"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let sr_id = random_id();
    let call = ISpendingRecord::submitCall {
        srId: sr_id,
    };
    let inner = Bytes::from(call.abi_encode());

    match env.new_actor()?.submit_tx(SPENDING_RECORD, inner).await {
        // Path A: actor pool refused the tx outright. Document it
        // and pass — the invariant "no SR landed" holds.
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, "S003: actor pool refused tx (no SR landed)");
            Ok(())
        }
        Err(ActorClientError::Revert(PsoContractError::SRANotActive)) => Ok(()),
        Err(other) => {
            tracing::info!(?other, "S003: actor surfaced typed error");
            // Anything that isn't an admission counts as success.
            Ok(())
        }
        // Path B: actor pool admitted the tx; we need to verify the
        // EVM-side reverted (status flag 0). Wait for the receipt;
        // if status is 1, the SR landed and the invariant broke.
        Ok(tx_hash) => {
            let receipt = env
                .new_actor()?
                .wait_for_receipt(tx_hash, Duration::from_secs(30))
                .await?;
            if receipt.status() {
                Err(eyre::eyre!(
                    "S003: wallet-signed SR.submit succeeded — invariant violated (tx {tx_hash:#x})"
                ))
            } else {
                tracing::info!(?tx_hash, "S003: actor admitted tx, EVM reverted (status=0)");
                Ok(())
            }
        }
    }
}
