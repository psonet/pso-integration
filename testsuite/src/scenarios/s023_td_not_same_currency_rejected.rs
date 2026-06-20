//! S023 — `TributeDraft.submit` rejects two SUs that don't share
//! the same `currency`.
//!
//! `_collectSuTotals` pins `acc.currency = first.currency`
//! from suIds[0] and asserts every subsequent SU matches. A
//! mismatch reverts with `NotSameCurrency()`.
//!
//! Approach: mint two SUs with the same worldwide_day but
//! currencies EUR (978) and USD (840). TD bundles both;
//! the contract sees the currency mismatch on suIds[1] and reverts.

use std::time::Duration;

use alloy_primitives::{Bytes, FixedBytes, U256};
use async_trait::async_trait;

use pso_chain_abi::addresses::TRIBUTE_DRAFT;
use pso_chain_abi::interfaces::ITributeDraft;

use crate::bridge::SuMintArgs;
use crate::data::{random_id, random_su_args};
use crate::{decode_text, PsoContractError, Scenario, TestEnv};

const EUR: u16 = 978;
const USD: u16 = 840;

pub struct S023;

#[async_trait]
impl Scenario for S023 {
    fn id(&self) -> &'static str {
        "S023"
    }
    fn description(&self) -> &'static str {
        "TD.submit with SUs in different currencies reverts NotSameCurrency"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let shape = random_su_args();
    let day = shape.worldwide_day;

    let su_a = mint_su_with(env, EUR, day, shape.amount_base).await?;
    let su_b = mint_su_with(env, USD, day, shape.amount_base).await?;
    tracing::info!(scenario = "S023", %su_a, %su_b, "minted two SUs in EUR + USD");

    let provider = env.attester_zero.inner().write_provider()?;
    let td = ITributeDraft::new(TRIBUTE_DRAFT, provider);

    let err = td
        .submit(
            random_id(),
            FixedBytes::from([0u8; 32]),
            vec![su_a, su_b],
            Bytes::new(),
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("S023: expected NotSameCurrency revert, got success"))?;

    let typed = decode_text(&format!("{err}"));
    match &typed {
        PsoContractError::NotSameCurrency => Ok(()),
        other => Err(eyre::eyre!("S023: expected NotSameCurrency, got {other}")),
    }
}

async fn mint_su_with(
    env: &TestEnv,
    currency: u16,
    worldwide_day: u32,
    base: u64,
) -> eyre::Result<U256> {
    let sr_id = random_id();
    let tx = env.attester_zero.register_spending_record(sr_id).await?;
    env.attester_zero
        .wait_for_tx_success(tx, Duration::from_secs(30))
        .await?;
    env.attester_zero
        .wait_for_sr_existence(&[sr_id], &[], Duration::from_secs(30))
        .await?;

    // Fresh consent per SU (distinct owners).
    let wallet = pso_mobile_integration::Wallet::new();
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let consent = wallet
        .generate_consent(seed.to_vec())
        .map_err(|e| eyre::eyre!("consent: {e:?}"))?;
    let consent_pk = consent
        .public_key()
        .map_err(|e| eyre::eyre!("consent pk: {e:?}"))?;
    let receipt = env
        .bridge
        .mint_su(SuMintArgs {
            consent_pk,
            referrer_address: alloy_primitives::Address::ZERO,
            currency,
            worldwide_day,
            amount_base: base,
            amount_atto: 0,
            sr_ids: vec![sr_id],
            amendment_sr_ids: vec![],
        })
        .await?;
    env.attester_zero
        .wait_for_su_existence(&[receipt.su_id], Duration::from_secs(30))
        .await?;
    Ok(receipt.su_id)
}
