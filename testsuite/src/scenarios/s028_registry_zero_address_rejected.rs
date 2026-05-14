//! S028 — `SRARegistry.register(address(0), ...)` reverts with
//! `ZeroAddress()`.
//!
//! Among the SRARegistry guards (`onlyAdmin` first), the body of
//! `register` checks `sra == address(0)` and reverts before
//! `permissionMask == 0` (the InvalidMask check, see S029). So we
//! call from the admin signer to clear the gate, supply
//! `address(0)`, and expect `ZeroAddress`.

use alloy::primitives::Address;
use async_trait::async_trait;

use pso_l2_client::PsoContractError;

use crate::clients::sra::into_pso_error;
use crate::{Scenario, TestEnv};

pub struct S028;

#[async_trait]
impl Scenario for S028 {
    fn id(&self) -> &'static str {
        "S028"
    }
    fn description(&self) -> &'static str {
        "SRARegistry.register(address(0), ...) reverts ZeroAddress"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let err = env
        .admin
        .register_sra(Address::ZERO, u32::MAX, 1_000_000u64, false)
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S028: expected ZeroAddress revert, got success"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::ZeroAddress => Ok(()),
        other => Err(eyre::eyre!("S028: expected ZeroAddress, got {other}")),
    }
}
