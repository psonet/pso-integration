//! S028 — `SRARegistry.register(address(0), ...)` reverts with
//! `ZeroAddress()`.
//!
//! Among the SRARegistry guards (`onlyAdmin` first), the body of
//! `register` checks `sra == address(0)` and reverts before
//! `permissionMask == 0` (the InvalidMask check, see S029). So we
//! call from the admin signer to clear the gate, supply
//! `address(0)`, and expect `ZeroAddress`.

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
    let admin = L2Client::connect_with_signer(&env.rpc_url, env.chain_id, &env.admin_key)
        .map_err(|e| eyre::eyre!("admin client: {e}"))?;
    let provider = admin
        .write_provider()
        .map_err(|e| eyre::eyre!("admin write_provider: {e}"))?;
    let reg = ISRARegistryView::new(SRA_REGISTRY, provider);

    let err = reg
        .register(Address::ZERO, u32::MAX, 1_000_000u64, false)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S028: expected ZeroAddress revert, got success"))?;

    let typed = into_pso_error(L2ClientError::Contract(format!("{err}")));
    match &typed {
        PsoContractError::ZeroAddress => Ok(()),
        other => Err(eyre::eyre!("S028: expected ZeroAddress, got {other}")),
    }
}
