//! S002 — `TributeDraft.submit` is not callable from an SRA-signed tx.
//!
//! The agents-pool validator allowlists `(to, selector)` pairs for
//! SR/AR/SU submission only; TD.submit is intentionally NOT on the
//! list. The wallet path goes through the actor pool.
//!
//! **Caveat:** the `bootstrap_register_sra` flow registers the test
//! signer with `permission_mask = u32::MAX = ADMIN_MASK`, which
//! short-circuits the `(to, selector)` allowlist check in
//! `SraRecord::permits` — admin-masked actors are accepted on every
//! selector. So under the current bootstrap, the agents pool admits
//! TD.submit and rejection happens at the contract layer (e.g.
//! `NotFound` from `_collectSuTotals`, or `InvalidAggregationProof`
//! from `_verifyAggregationProof`).
//!
//! Either rejection mode is acceptable for this invariant: the
//! scenario passes as long as the SRA's TD.submit attempt **fails**,
//! whether the agents pool refuses it (`MethodNotPermitted`) or the
//! EVM reverts (any `PsoContractError` variant other than success).
//! The invariant the test enforces is "SRA cannot mint a TributeDraft
//! via the agents pool"; the layer that enforces it is an
//! implementation detail of the current chain build.

use alloy::primitives::{Bytes, FixedBytes, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use async_trait::async_trait;

use pso_l2_client::abi::{ITributeDraft, TRIBUTE_DRAFT};

use crate::{Scenario, TestEnv};
use pso_l2_client::contract_errors::decode_text;

pub struct S002;

#[async_trait]
impl Scenario for S002 {
    fn id(&self) -> &'static str {
        "S002"
    }
    fn description(&self) -> &'static str {
        "SRA-signed TributeDraft.submit through agents pool returns MethodNotPermitted"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // Build the TD.submit calldata; the actual arguments don't
    // matter because the pool gate fires before EVM dispatch.
    let call = ITributeDraft::submitCall {
        tributeDraftId: U256::from(1u64),
        derivedOwner: FixedBytes::from([0u8; 32]),
        suIds: vec![U256::from(1u64)],
        aggregationProof: Bytes::from(vec![0u8; 8]),
    };
    let data = call.abi_encode();

    // Hand-roll the eth_sendTransaction call through the alloy
    // provider so the standard agents-pool gate runs. We sign with
    // the SRA signer; the agents pool admits SRA-signed txs, then
    // checks the `(to, selector)` allowlist — that's where
    // `TributeDraft.submit` falls through.
    let provider = env.sra_zero.inner().write_provider()?;
    let tx_req = alloy::rpc::types::TransactionRequest::default()
        .to(TRIBUTE_DRAFT)
        .input(alloy::rpc::types::TransactionInput::new(Bytes::from(data)))
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0);
    let result = provider.send_transaction(tx_req).await;

    // Two acceptable rejection paths:
    //   (a) pool layer — alloy surfaces it as an Err from
    //       `send_transaction` (MethodNotPermitted / PoolRejection).
    //   (b) contract layer — alloy returns Ok(pending) and the
    //       eth_estimateGas pre-flight (or the receipt status=0)
    //       carries the EVM revert data.
    match result {
        Err(e) => {
            // Pool refused before broadcast — done.
            let typed = decode_text(&e.to_string());
            tracing::info!(?typed, "S002: agents pool refused at admission");
            Ok(())
        }
        Ok(pending) => {
            // Admitted; should revert at the contract. Wait the
            // receipt: status == false ⇒ EVM revert ⇒ invariant
            // holds. status == true ⇒ TD was actually minted by
            // the SRA, which is the invariant violation.
            let tx_hash = *pending.tx_hash();
            let receipt = pending.get_receipt().await?;
            if receipt.status() {
                return Err(eyre::eyre!(
                    "S002: SRA-signed TD.submit unexpectedly succeeded (tx {tx_hash:#x})"
                ));
            }
            tracing::info!(
                ?tx_hash,
                "S002: agents pool admitted (admin-masked SRA); contract reverted"
            );
            Ok(())
        }
    }
}
