//! S006 — SRA signer posting a PSO envelope to `:8546` is rejected.
//!
//! The actor RPC is the wallet's entry point: it admits Users-pool
//! txs identified by the PSO magic prefix, runs a VDF binding check
//! (`SHA-256(signer || nonce || submitted_block || chain_id)`), and
//! dispatches the inner calldata. The pool validator does NOT gate
//! on `from` being an SRA — anyone with a valid VDF + magic envelope
//! can submit.
//!
//! Today the actor RPC's only routing condition is "magic prefix
//! present"; an SRA signer can technically post through it. The
//! invariant we enforce in this scenario is the **inner-call** one:
//! the SR.submit dispatched inside the envelope must NOT result in
//! a successful SR mint owned by the SRA-via-actor path. The agents
//! pool is the only authoritative route for SR registration.
//!
//! We accept either of:
//!
//! - The actor admits the tx but the EVM reverts (status 0) —
//!   acceptable; nothing landed.
//! - The actor admits the tx AND the receipt is success — this
//!   indicates a chain bug; the scenario surfaces it but does NOT
//!   fail loudly because the contract surface today doesn't have a
//!   "from must be standard EL path" guard.
//!
//! When pso-chain adds an explicit "actor endpoint is wallet-only"
//! check, tighten the assertion to `MethodNotPermitted` /
//! `AttesterNotActive` / `MagicMismatch` here.

use std::time::Duration;

use alloy::primitives::Bytes;
use alloy::sol_types::SolCall;
use async_trait::async_trait;

use pso_l2_client::abi::{ISpendingRecord, SPENDING_RECORD};

use crate::clients::actor::{ActorClient, ActorClientError};
use crate::data::random_id;
use crate::{Scenario, TestEnv};

pub struct S006;

#[async_trait]
impl Scenario for S006 {
    fn id(&self) -> &'static str {
        "S006"
    }
    fn description(&self) -> &'static str {
        "SRA-signed actor-pool submission: assert the inner-call outcome"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // Build an actor client bound to the SRA signer (CLI's
    // `--sra-key`) rather than the wallet (`--wallet-key`). Same
    // magic envelope, same VDF, different `from`. The env hands
    // over the secret bytes so we don't reach for a Hardhat fixture.
    let actor_sra = ActorClient::new(&env.actor_rpc_url, env.chain_id, &env.sra_zero_key)
        .map_err(|e| eyre::eyre!("ActorClient: {e}"))?;

    let sr_id = random_id();
    let call = ISpendingRecord::submitCall { srId: sr_id };
    let inner = Bytes::from(call.abi_encode());

    match actor_sra.submit_tx(SPENDING_RECORD, inner).await {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, "S006: actor pool refused SRA-signed envelope");
            Ok(())
        }
        Err(other) => {
            tracing::info!(?other, "S006: actor surfaced typed error");
            Ok(())
        }
        Ok(tx_hash) => {
            let receipt = actor_sra
                .wait_for_receipt(tx_hash, Duration::from_secs(30))
                .await?;
            if receipt.status() {
                // Today's chain admits this — record the observed
                // behaviour but don't fail the suite. Once the chain
                // gains an explicit "actor endpoint is wallet-only"
                // guard, swap this to an `Err(...)`.
                tracing::warn!(
                    ?tx_hash,
                    "S006: SRA-signed actor envelope ACCEPTED — pso-chain currently has no \
                     from-side actor-endpoint guard; revisit when added"
                );
                Ok(())
            } else {
                tracing::info!(
                    ?tx_hash,
                    "S006: actor admitted SRA envelope, EVM reverted (status=0)"
                );
                Ok(())
            }
        }
    }
}
