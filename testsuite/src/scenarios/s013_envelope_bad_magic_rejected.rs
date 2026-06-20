//! S013 — users RPC rejects an anonymous-lane envelope whose `0x76`
//! type byte has been clobbered.
//!
//! The research node discriminates the anonymous lane by the EIP-2718
//! type byte `0x76` (it replaced pso-chain's `0xCAFED00D` calldata
//! magic). The users RPC accepts ONLY `0x76` transactions; any other
//! type byte is refused. We zero the type byte post-build and expect a
//! `PoolRejection` from `eth_sendRawTransaction`. The rest of the
//! envelope stays valid so the discriminator is the only trigger.
use crate::clients::actor::ActorClientError;
use crate::data::random_id;
use crate::{Scenario, TestEnv};
use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use async_trait::async_trait;
use pso_chain_abi::addresses::SPENDING_RECORD;
use pso_chain_abi::interfaces::ISpendingRecord;
pub struct S013;
#[async_trait]
impl Scenario for S013 {
    fn id(&self) -> &'static str {
        "S013"
    }
    fn description(&self) -> &'static str {
        "users RPC rejects envelope with a clobbered 0x76 type byte"
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
        .new_actor_as_attester_zero()?
        .submit_tx_with_envelope(SPENDING_RECORD, inner, |mut env_bytes| {
            // Clobber the 0x76 type byte (the anonymous-lane discriminator);
            // the users RPC then sees a non-0x76 tx and refuses it.
            env_bytes[0] = 0x00;
            tracing::info!(
                target: "pso_e2e::scenario",
                scenario = "S013",
                step = "tamper",
                "clobbered 0x76 type byte"
            );
            env_bytes
        })
        .await;
    match result {
        Err(ActorClientError::PoolRejection(msg)) => {
            tracing::info!(%msg, scenario = "S013", "actor pool refused tampered-magic envelope");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S013: expected PoolRejection on bad magic, got {other}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S013: expected pool rejection but actor admitted tx {:?}",
            tx
        )),
    }
}
