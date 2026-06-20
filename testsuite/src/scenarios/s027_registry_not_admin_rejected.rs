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

use alloy_primitives::Address;
use alloy_sol_types::sol;
use async_trait::async_trait;

use crate::{decode_text, PsoContractError, Scenario, TestEnv};

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
    alloy_primitives::address!("5200000000000000000000000000000000000001");

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
            alloy_primitives::B256::ZERO,
            alloy_primitives::U256::ZERO,
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S027: expected NotAdmin revert, got success"))?;

    let typed = decode_text(&format!("{err}"));
    match &typed {
        PsoContractError::NotAdmin => Ok(()),
        other => Err(eyre::eyre!("S027: expected NotAdmin, got {other}")),
    }
}
