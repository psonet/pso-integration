//! S027 — `AttestersRegistry.register` from a non-admin signer reverts
//! with `NotAdmin`.
//!
//! The registry's `onlyAdmin` modifier guards every state-mutating
//! entrypoint (`register`, `revoke`, `updateMask`,
//! `setRotationCandidate`, `initiateAdminTransfer`). A non-admin
//! caller fails the `msg.sender != admin` check immediately.
//!
//! We use the SRA client (env.sra_zero) — it's an active SRA, but NOT
//! the admin — to call register; the contract reverts before
//! looking at the arguments, so any plausible `sra` / `mask` works.

use alloy::primitives::Address;
use alloy::sol;
use async_trait::async_trait;

use pso_l2_client::L2ClientError;

use crate::clients::sra::into_pso_error;
use crate::{PsoContractError, Scenario, TestEnv};

sol! {
    #[sol(rpc)]
    interface IAttestersRegistryView {
        function register(
            address attester,
            uint32 permissionMask,
            bool isRotationCandidate,
            bytes32 consensusKey,
            uint256 p2pAddr
        ) external;
    }
}

const SRA_REGISTRY: Address =
    alloy::primitives::address!("5200000000000000000000000000000000000001");

pub struct S027;

#[async_trait]
impl Scenario for S027 {
    fn id(&self) -> &'static str {
        "S027"
    }
    fn description(&self) -> &'static str {
        "AttestersRegistry.register from non-admin reverts NotAdmin"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // The SRA signer is active but NOT the admin — perfect impostor.
    let provider = env.sra_zero.inner().write_provider()?;
    let reg = IAttestersRegistryView::new(SRA_REGISTRY, provider);

    // Pick a plausible-but-otherwise-irrelevant fresh address to
    // "register". The contract reverts at the admin gate first;
    // arguments don't matter.
    let fake = Address::from([0xab; 20]);

    let err = reg
        .register(
            fake,
            u32::MAX,
            false,
            alloy::primitives::B256::ZERO,
            alloy::primitives::U256::ZERO,
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S027: expected NotAdmin revert, got success"))?;

    let typed = into_pso_error(L2ClientError::Contract(format!("{err}")));
    match &typed {
        PsoContractError::NotAdmin => Ok(()),
        other => Err(eyre::eyre!("S027: expected NotAdmin, got {other}")),
    }
}
