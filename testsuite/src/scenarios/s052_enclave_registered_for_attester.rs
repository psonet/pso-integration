//! S052 — a bank-data-provider enclave becomes usable through the registry.
//!
//! On a real network `register` proves the deployment with an SEV-SNP report
//! verified by `0x0206`. A devnet runs the provider's Local profile, whose
//! attestation document that precompile cannot verify by construction, so
//! genesis sets `devnetAdminRegister` and governance creates the record
//! instead — the same record, reached by the path devnets are given.
//!
//! What this pins is the consumer's side of it: after the record exists,
//! `isActiveFor(enclavePk, attester, providerId)` is true for the attester who
//! owns it and false for anyone else and for any other provider. That cascade
//! is what `SpendingUnitV2.submitSU` gates every settlement on, and S053
//! settles against this record.

use alloy_primitives::{address, keccak256, Address, B256};
use async_trait::async_trait;

use super::registries::{enclave_key, IEnclaveRegistry};
use crate::{Scenario, TestEnv};

/// The canonical predeploy (`pso_chain_abi::addresses::ENCLAVE_REGISTRY`).
const ENCLAVE_REGISTRY: Address = address!("5200000000000000000000000000000000000002");

/// The devnet provider genesis seeds (`mock`, no release requirement).
pub fn provider_id() -> B256 {
    keccak256("mock")
}

/// The manifest digest the deployment is registered with — what `submitSU`
/// rebuilds the settlement statement with, so S053 signs under it.
pub fn rm_digest() -> B256 {
    keccak256("S052 runtime manifest")
}

/// Launch measurement of the devnet enclave. Allowlisted here so `isActive`'s
/// measurement cascade is satisfied rather than bypassed.
fn measurement_hash() -> B256 {
    keccak256("S052 measurement")
}

pub struct S052;

#[async_trait]
impl Scenario for S052 {
    fn id(&self) -> &'static str {
        "S052"
    }
    fn description(&self) -> &'static str {
        "enclave deployment registered on devnet is active for its attester only"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let (_, enclave_pk) = enclave_key();
    let attester = env.attester_zero.address();
    let registry = IEnclaveRegistry::new(ENCLAVE_REGISTRY, env.admin.inner().write_provider()?);

    eyre::ensure!(
        registry.devnetAdminRegister().call().await?,
        "the devnet genesis must set devnetAdminRegister for this path to exist"
    );

    if !registry
        .isActiveFor(enclave_pk, attester, provider_id())
        .call()
        .await?
    {
        registry
            .setMeasurement(measurement_hash(), true)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await?
            .get_receipt()
            .await?;
        registry
            .adminRegister(
                enclave_pk,
                attester,
                rm_digest(),
                provider_id(),
                keccak256("mock://Mock Bank"),
                measurement_hash(),
            )
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    eyre::ensure!(
        registry
            .isActiveFor(enclave_pk, attester, provider_id())
            .call()
            .await?,
        "the registered deployment must be active for its own attester"
    );

    // The record names one attester and one provider. Both are part of what
    // `submitSU` checks, so both refusals matter.
    eyre::ensure!(
        !registry
            .isActiveFor(enclave_pk, Address::repeat_byte(0xEE), provider_id())
            .call()
            .await?,
        "the deployment must not be active for another attester"
    );
    eyre::ensure!(
        !registry
            .isActiveFor(enclave_pk, attester, keccak256("yapily"))
            .call()
            .await?,
        "the deployment must not be active under another provider"
    );
    eyre::ensure!(
        !registry
            .isActiveFor(B256::repeat_byte(0xAB), attester, provider_id())
            .call()
            .await?,
        "an unregistered enclave key must not be active"
    );
    Ok(())
}
