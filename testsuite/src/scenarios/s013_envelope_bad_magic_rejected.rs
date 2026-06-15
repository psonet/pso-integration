//! S013 — actor RPC rejects a Users-pool envelope whose magic
//! prefix bytes are zeroed out.
//!
//! The 172-byte PSO header begins with a 4-byte magic prefix
//! (`0xCAFED00D` by default — see [`crate::clients::envelope::
//! DEFAULT_PSO_MAGIC`]). The actor RPC's pool validator MUST
//! refuse any submission that doesn't start with that exact prefix;
//! the magic is the only thing distinguishing a Users-pool tx from
//! a regular EL tx that happened to land on `:8546`.
//!
//! We mutate the envelope post-build to zero out bytes [0..4) and
//! expect a `PoolRejection` from `eth_sendRawTransaction`. The rest
//! of the header (nullifier / VDF / submitted_block) stays valid so
//! the magic check is the only thing the chain could be reacting to.
use crate::clients::actor::ActorClientError;
use crate::data::random_id;
use crate::{Scenario, TestEnv};
use alloy::primitives::Bytes;
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use pso_l2_client::abi::{ISpendingRecord, SPENDING_RECORD};
pub struct S013;
#[async_trait]
impl Scenario for S013 {
    fn id(&self) -> &'static str {
        "S013"
    }
    fn description(&self) -> &'static str {
        "actor RPC rejects envelope with zeroed magic prefix"
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
        .submit_tx_with_envelope(SPENDING_RECORD, inner, |mut env_bytes| {
            // First 4 bytes are the magic prefix; clobber.
            env_bytes[0] = 0x00;
            env_bytes[1] = 0x00;
            env_bytes[2] = 0x00;
            env_bytes[3] = 0x00;
            tracing::info!(
                target: "pso_e2e::scenario",
                scenario = "S013",
                step = "tamper",
                first_4_bytes = "00000000",
                "zeroed magic prefix"
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
