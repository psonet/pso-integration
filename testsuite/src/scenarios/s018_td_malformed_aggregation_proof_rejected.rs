//! S018 — `TributeDraft.submit` rejects an empty `aggregationProof`
//! payload with `MalformedAggregationProof`.
//!
//! The contract validates the proof in three layered ways
//! (`TributeDraft.sol::_verifyAggregationProof`, lines 240-263):
//!
//! 1. **Length check** — `combinedProof.length < headerLen` reverts
//!    with `MalformedAggregationProof`. `headerLen = 4 + k*32`
//!    where `k = expectedPublicInputs.length`. For tier 1 (1 SU)
//!    that's `4 + 2*32 = 68` bytes.
//! 2. **`num_inputs` prefix sanity** — the first 4 bytes must
//!    BE-decode to `k`; otherwise also `MalformedAggregationProof`.
//! 3. **Public-input + SNARK verify** — anything getting past (1)
//!    and (2) and mismatching the on-chain reconstruction or the
//!    zk_verify precompile reverts with `InvalidAggregationProof`
//!    (S019 covers this path).
//!
//! Approach:
//! - Register an SR, mint an SU via the bridge so the on-chain
//!   `SU.getData(suId)` lookup inside `_collectSuTotals` succeeds
//!   (without this we'd hit `NotFound` before the proof check).
//! - Submit a TD whose proof field is `bytes("")` — zero bytes —
//!   so the length check fires.
//! - Decode the revert; expect `MalformedAggregationProof`.

use std::time::Duration;

use alloy_primitives::{Bytes, FixedBytes, U256};
use async_trait::async_trait;

use pso_chain_abi::addresses::TRIBUTE_DRAFT;
use pso_chain_abi::interfaces::ITributeDraft;

use crate::bridge::SuMintArgs;
use crate::data::{random_id, random_su_args};
use crate::{decode_text, PsoContractError, Scenario, TestEnv};

pub struct S018;

#[async_trait]
impl Scenario for S018 {
    fn id(&self) -> &'static str {
        "S018"
    }
    fn description(&self) -> &'static str {
        "TD.submit with empty aggregationProof reverts MalformedAggregationProof"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let su_id = mint_one_su(env).await?;
    tracing::info!(scenario = "S018", step = "su-minted", %su_id, "minted SU for TD reference");

    let provider = env.attester_zero.inner().write_provider()?;
    let td = ITributeDraft::new(TRIBUTE_DRAFT, provider);

    let err = td
        .submit(
            random_id(),
            FixedBytes::from([0u8; 32]),
            vec![su_id],
            Bytes::new(),
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S018: expected revert on empty proof, got success"))?;

    let typed = decode_text(&format!("{err}"));
    match &typed {
        PsoContractError::MalformedAggregationProof => Ok(()),
        other => Err(eyre::eyre!(
            "S018: expected MalformedAggregationProof, got {other}"
        )),
    }
}

/// Boilerplate: register an SR, then mint one SU via the bridge.
/// Returned `su_id` is live in the canonical SU storage.
async fn mint_one_su(env: &TestEnv) -> eyre::Result<U256> {
    let sr_id = random_id();
    let tx = env.attester_zero.register_spending_record(sr_id).await?;
    env.attester_zero
        .wait_for_tx_success(tx, Duration::from_secs(30))
        .await?;
    env.attester_zero
        .wait_for_sr_existence(&[sr_id], &[], Duration::from_secs(30))
        .await?;

    // The wallet's consent public key (32-byte PsoV1 point) — the
    // attester FFI issues against it. Any valid consent works; this SU
    // only needs to exist for the TD's `getData(suId)` lookup.
    let wallet = pso_mobile_integration::Wallet::new();
    let consent = wallet
        .generate_consent(vec![0x18; 32])
        .map_err(|e| eyre::eyre!("consent: {e:?}"))?;
    let consent_pk = consent
        .public_key()
        .map_err(|e| eyre::eyre!("consent pk: {e:?}"))?;
    let shape = random_su_args();
    let args = SuMintArgs {
        consent_pk,
        referrer_address: alloy_primitives::Address::ZERO,
        currency: shape.currency,
        worldwide_day: shape.worldwide_day,
        amount_base: shape.amount_base,
        amount_atto: shape.amount_atto,
        sr_ids: vec![sr_id],
        amendment_sr_ids: vec![],
    };
    let receipt = env.bridge.mint_su(args).await?;
    env.attester_zero
        .wait_for_su_existence(&[receipt.su_id], Duration::from_secs(30))
        .await?;
    Ok(receipt.su_id)
}
