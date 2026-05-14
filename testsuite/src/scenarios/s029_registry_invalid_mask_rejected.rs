//! S029 — `SRARegistry.register(addr, 0, ...)` reverts with
//! `InvalidMask()`.
//!
//! After the `onlyAdmin` gate and `sra != address(0)` check
//! (S028's path), `register` validates the permission bitmask:
//! `permissionMask == 0` reverts with `InvalidMask`. We call as
//! admin with a fresh non-zero address but `mask = 0`.

use alloy::primitives::Address;
use alloy::sol;
use async_trait::async_trait;

use pso_l2_client::{L2Client, L2ClientError, PsoContractError};

use crate::clients::sra::into_pso_error;
use crate::{Scenario, TestEnv};

sol! {
    #[sol(rpc)]
    interface ISRARegistryView {
        function register(
            address sra,
            uint32 permissionMask,
            uint64 rateLimit,
            bool isRotationCandidate
        ) external;
    }
}

const SRA_REGISTRY: Address =
    alloy::primitives::address!("5200000000000000000000000000000000000001");

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
    let admin = L2Client::connect_with_signer(&env.rpc_url, env.chain_id, &env.admin_key)
        .map_err(|e| eyre::eyre!("admin client: {e}"))?;
    let provider = admin
        .write_provider()
        .map_err(|e| eyre::eyre!("admin write_provider: {e}"))?;
    let reg = ISRARegistryView::new(SRA_REGISTRY, provider);

    let fake = Address::from([0xab; 20]);

    let err = reg
        .register(fake, 0u32, 1_000_000u64, false)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S029: expected InvalidMask revert, got success"))?;

    let typed = into_pso_error(L2ClientError::Contract(format!("{err}")));
    match &typed {
        PsoContractError::InvalidMask => Ok(()),
        other => Err(eyre::eyre!("S029: expected InvalidMask, got {other}")),
    }
}
