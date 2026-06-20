//! S037 — admin `revoke_sra(addr)` against a never-registered
//! address reverts with `NotRegistered(addr)`.
//!
//! The mirror of S034 (registering an already-registered address
//! is rejected): revoking an unknown address is *also* rejected,
//! rather than silently being a no-op. Important because a
//! permissive "best-effort revoke" implementation could let the
//! admin think they've revoked an address that was actually
//! never bound — leaving a live SRA assumed dead.

use alloy_primitives::Address;
use async_trait::async_trait;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::clients::sra::into_pso_error;
use crate::{PsoContractError, Scenario, TestEnv};

pub struct S037;

#[async_trait]
impl Scenario for S037 {
    fn id(&self) -> &'static str {
        "S037"
    }
    fn description(&self) -> &'static str {
        "admin.revoke_sra against a never-registered address reverts NotRegistered(addr)"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // Cryptographically random address — collisions with the
    // genesis registry contents (Hardhat #0, Hardhat #1, any
    // freshly minted SRA from a prior scenario) are negligible.
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    let phantom = Address::from(bytes);

    let err = env
        .admin
        .revoke_sra(phantom)
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S037: expected NotRegistered revert, got success"))?;

    let typed = into_pso_error(err);
    match &typed {
        PsoContractError::NotRegistered(echoed) => {
            if *echoed != phantom {
                return Err(eyre::eyre!(
                    "S037: NotRegistered echoed wrong address: got {echoed}, expected {phantom}"
                ));
            }
            Ok(())
        }
        other => Err(eyre::eyre!("S037: expected NotRegistered(_), got {other}")),
    }
}
