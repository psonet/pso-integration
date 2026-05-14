//! S029 — `SRARegistry.register(addr, 0, ...)` reverts with
//! `InvalidMask()`.
//!
//! After the `onlyAdmin` gate and `sra != address(0)` check
//! (S028's path), `register` validates the permission bitmask:
//! `permissionMask == 0` reverts with `InvalidMask`. We call as
//! admin with a fresh non-zero address but `mask = 0`.

use alloy::primitives::Address;
use async_trait::async_trait;

use pso_l2_client::PsoContractError;

use crate::clients::sra::into_pso_error;
use crate::{Scenario, TestEnv};

pub struct S029;

#[async_trait]
impl Scenario for S029 {
    fn id(&self) -> &'static str {
        "S029"
    }
    fn description(&self) -> &'static str {
        "SRARegistry.register with permissionMask=0 reverts InvalidMask"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let fake = Address::from([0xab; 20]);
    let err = env
        .admin
        .register_sra(fake, 0u32, 1_000_000u64, false)
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S029: expected InvalidMask revert, got success"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::InvalidMask => Ok(()),
        other => Err(eyre::eyre!("S029: expected InvalidMask, got {other}")),
    }
}
