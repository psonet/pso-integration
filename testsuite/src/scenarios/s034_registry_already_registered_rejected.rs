//! S034 — admin re-registering an already-registered SRA reverts
//! with `AlreadyRegistered(address)`.
//!
//! `SRARegistry.register(sra, mask, rl, rc)` keeps a single record
//! per address (an SRA can be registered/revoked, not registered
//! twice). The contract's first guard after the `onlyAdmin` /
//! `address(0)` / `mask == 0` checks is the per-address dedupe.
//!
//! Approach: spawn a fresh SRA via [`TestEnv::new_sra`] (which
//! goes through `admin.register_sra` itself), then call
//! `admin.register_sra` against the same address a second time
//! with different parameters. Expect the typed
//! `AlreadyRegistered(addr)` payload, with the address echoed
//! back so the test can verify it's exactly the duplicate we
//! tried to re-register.

use async_trait::async_trait;

use pso_l2_client::PsoContractError;

use crate::clients::sra::into_pso_error;
use crate::{Scenario, TestEnv};

pub struct S034;

#[async_trait]
impl Scenario for S034 {
    fn id(&self) -> &'static str {
        "S034"
    }
    fn description(&self) -> &'static str {
        "SRARegistry.register on an already-registered address reverts AlreadyRegistered(addr)"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let sra = env.new_sra().await?;
    let addr = sra.address();
    tracing::info!(scenario = "S034", %addr, "spawned fresh SRA");

    // Second register call against the same address. Use a
    // different mask / rate-limit so a permissive "idempotent
    // overwrite" implementation would visibly mutate the record
    // — the typed revert is the only correct behaviour.
    let err = env
        .admin
        .register_sra(addr, 0x00FF_FFFF, 999u64, false)
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S034: expected AlreadyRegistered revert, got success"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::AlreadyRegistered(echoed) => {
            if *echoed != addr {
                return Err(eyre::eyre!(
                    "S034: AlreadyRegistered echoed wrong address: got {echoed}, expected {addr}"
                ));
            }
            Ok(())
        }
        other => Err(eyre::eyre!(
            "S034: expected AlreadyRegistered(_), got {other}"
        )),
    }
}
