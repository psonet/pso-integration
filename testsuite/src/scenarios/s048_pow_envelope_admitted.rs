//! S048 — a `0x77` anti-spam envelope is admitted and executes.
//!
//! The happy path for SR-43. Every other users-lane scenario in this suite
//! builds the legacy `0x76` envelope, whose MinRoot proof is forgeable in O(1)
//! — so before this existed, **nothing here exercised the format the chain
//! actually wants clients to use**. A node could have rejected every `0x77`
//! transaction and the whole suite would still have gone green.
//!
//! That is not hypothetical: exactly such a break shipped on the node's own
//! branch, where the users RPC gated on the `0x76` type byte alone and refused
//! every `0x77` submission before the pool ever saw it.
//!
//! Asserts the full path, not just admission: the transaction is accepted by
//! the actor RPC AND mined with `status = 1`. Admission alone would pass even
//! if the envelope were stripped incorrectly and the inner call never ran.
use core::time::Duration;

use crate::data::random_id;
use crate::{Scenario, TestEnv};
use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use async_trait::async_trait;
use pso_chain_abi::addresses::SPENDING_RECORD;
use pso_chain_abi::interfaces::ISpendingRecord;

pub struct S048;

#[async_trait]
impl Scenario for S048 {
    fn id(&self) -> &'static str {
        "S048"
    }
    fn description(&self) -> &'static str {
        "users RPC admits a 0x77 PoW envelope and the inner call executes"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let sr_id = random_id();
    let call = ISpendingRecord::submitCall { srId: sr_id };
    let inner = Bytes::from(call.abi_encode());

    let actor = env.new_actor_as_attester_zero()?;
    let tx = actor
        .submit_pow_tx(SPENDING_RECORD, inner, |bytes| bytes)
        .await
        .map_err(|e| eyre::eyre!("S048: 0x77 envelope rejected at admission: {e}"))?;

    tracing::info!(
        target: "pso_e2e::scenario",
        scenario = "S048",
        step = "admitted",
        ?tx,
        "0x77 envelope accepted by the users RPC"
    );

    let receipt = actor
        .wait_for_receipt(tx, Duration::from_secs(60))
        .await
        .map_err(|e| eyre::eyre!("S048: no receipt for {tx:#x}: {e}"))?;

    if !receipt.status() {
        return Err(eyre::eyre!(
            "S048: 0x77 tx {tx:#x} mined but reverted — the envelope was admitted, \
             so the anti-spam gate is fine; the inner call is what failed"
        ));
    }

    tracing::info!(
        target: "pso_e2e::scenario",
        scenario = "S048",
        step = "mined",
        ?tx,
        "0x77 envelope executed (status = 1)"
    );
    Ok(())
}
