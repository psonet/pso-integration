//! S017 — actor RPC rejects an envelope whose VDF output doesn't
//! match `MinRoot(vdf_input)`.
//!
//! The vdf_output field is at bytes [68..116) of the PSO header.
//! MinRoot is deterministic, so the chain knows what
//! `MinRoot(vdf_input, T)` is for the difficulty T; an output that
//! doesn't match is straight-up forged. This is distinct from S016
//! (bad proof against an otherwise-correct output): here the proof
//! corresponds to a *different* output than the one we put in the
//! header.
//!
//! Mutation: flip a byte in vdf_output. The proof field is left
//! intact, so the verifier sees `output mismatch` rather than
//! `proof invalid` — same `PoolRejection` shape either way, but
//! the path exercised is different.
use crate::clients::actor::ActorClientError;
use crate::data::random_id;
use crate::{Scenario, TestEnv};
use alloy::primitives::Bytes;
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use pso_l2_client::abi::{ISpendingRecord, SPENDING_RECORD};
pub struct S017;
#[async_trait]
impl Scenario for S017 {
    fn id(&self) -> &'static str {
        "S017"
    }
    fn description(&self) -> &'static str {
        "actor RPC rejects envelope with bit-flipped VDF output"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}
async fn run(env: &TestEnv) -> eyre::Result<()> {
    let sr_id = random_id();
    let call = ISpendingRecord::submitCall { srId: sr_id };
    let inner = Bytes::from(call.abi_encode());
    let result = env
        .new_actor_as_sra_zero()?
        .submit_tx_with_envelope(SPENDING_RECORD, inner, |mut bytes| {
            // Flip the last byte of the vdf_output field (0x76 wire range).
            // Any single-byte change makes the encoded output not equal
            // `MinRoot(vdf_input, T)`.
            bytes[crate::clients::envelope::VDF_OUTPUT_RANGE.end - 1] ^= 0x55;
            tracing::info!(
                target: "pso_e2e::scenario",
                scenario = "S017",
                step = "tamper",
                "bit-flipped last byte of vdf_output",
            );
            bytes
        })
        .await;
    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S017", "actor pool refused wrong-VDF-output envelope");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S017: expected PoolRejection on wrong VDF output, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S017: expected pool rejection but actor admitted tx {:?}",
            tx
        )),
    }
}
