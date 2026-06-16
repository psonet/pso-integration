//! S016 — actor RPC rejects an envelope whose VDF proof bytes have
//! been bit-flipped.
//!
//! Header layout (see [`crate::clients::envelope`]):
//! `[4B magic][32B nullifier][32B vdf_input][48B vdf_output]
//! [48B vdf_proof][8B submitted_block][inner]`.
//!
//! The vdf_proof field is at bytes [116..164). MinRoot verify is
//! deterministic over `(vdf_input, vdf_output, vdf_proof)`; flipping
//! a single byte in the proof makes the verifier reject, which the
//! actor RPC surfaces as a `PoolRejection`. The output is left
//! untouched on purpose — this isolates the proof-verify path from
//! the "output doesn't match input" path (S017 covers that).
use crate::clients::actor::ActorClientError;
use crate::data::random_id;
use crate::{Scenario, TestEnv};
use alloy::primitives::Bytes;
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use pso_l2_client::abi::{ISpendingRecord, SPENDING_RECORD};
pub struct S016;
#[async_trait]
impl Scenario for S016 {
    fn id(&self) -> &'static str {
        "S016"
    }
    fn description(&self) -> &'static str {
        "actor RPC rejects envelope with bit-flipped VDF proof"
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
            // Flip the first byte of the vdf_proof field (0x76 wire range).
            // Any change inside the proof invalidates MinRoot verify.
            bytes[crate::clients::envelope::VDF_PROOF_RANGE.start] ^= 0xAA;
            tracing::info!(
                target: "pso_e2e::scenario",
                scenario = "S016",
                step = "tamper",
                "bit-flipped first byte of vdf_proof",
            );
            bytes
        })
        .await;
    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S016", "actor pool refused bad-VDF-proof envelope");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S016: expected PoolRejection on bad VDF proof, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S016: expected pool rejection but actor admitted tx {:?}",
            tx
        )),
    }
}
