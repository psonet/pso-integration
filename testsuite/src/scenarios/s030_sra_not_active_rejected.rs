//! S030 — `SpendingRecord.submit` from a never-registered signer
//! reverts with `AttesterNotActive`.
//!
//! Every state-mutating entry point on the agents-pool path goes
//! through the `onlyActiveSRA` modifier (`ISRAAware`), which calls
//! `sraRegistry.isActive(_msgSender())`. A never-registered signer
//! sees `isActive == false` and the modifier reverts with
//! `AttesterNotActive()`. We roll a fresh secp256k1 key, build an
//! `SraClient` from it, and try to submit an SR — expect the
//! revert.

use async_trait::async_trait;

use crate::clients::sra::SraClient;
use crate::data::{random_id, random_secret_key};
use crate::{into_pso_error, PsoContractError, Scenario, TestEnv};

pub struct S030;

#[async_trait]
impl Scenario for S030 {
    fn id(&self) -> &'static str {
        "S030"
    }
    fn description(&self) -> &'static str {
        "SR.submit from never-registered SRA reverts AttesterNotActive"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // Roll a fresh key — never goes through `bootstrap_register_sra`,
    // so the registry reports `isActive(addr) == false`.
    let stranger_key = random_secret_key();
    let stranger = SraClient::new(&env.rpc_url, env.chain_id, &stranger_key)?;

    let sr_id = random_id();
    let err = stranger
        .register_spending_record(sr_id)
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S030: expected AttesterNotActive revert, got success"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::AttesterNotActive => Ok(()),
        other => Err(eyre::eyre!("S030: expected AttesterNotActive, got {other}")),
    }
}
