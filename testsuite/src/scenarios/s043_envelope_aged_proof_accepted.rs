//! S043 — an aged-but-inside-window proof is still admitted.
//!
//! Positive counterpart to S015 (stale rejection). Real wallets are
//! slow: the VDF takes ~2 s on phone hardware, the app may background
//! mid-compute, and the network adds latency — so by broadcast time
//! the proof's `submitted_block` is several blocks behind head. The
//! validator accepts iff `head - submitted_block ∈ [0, PSO_PROOF_MAX_AGE]`
//! (default 32). This scenario pins the *positive* edge of that
//! window: a proof aged ~`AGE_BLOCKS` blocks MUST be admitted and
//! executed.
//!
//! Mechanism: pin `submitted_block = H`, derive the VDF binding for
//! `H` (the proof is genuinely "as of" H — not tampered), then wait
//! until `head ≈ H + AGE_BLOCKS` before broadcasting.

use std::time::{Duration, Instant};

use alloy::primitives::{Bytes, U256};
use alloy::sol_types::SolCall;
use async_trait::async_trait;

use pso_l2_client::abi::TRIBUTE_DRAFT;

use crate::{Scenario, TestEnv};

/// How many blocks to age the proof before broadcast. Comfortably
/// inside the default 32-block window even if a couple more blocks
/// land between the last poll and pool admission.
const AGE_BLOCKS: u64 = 20;

pub struct S043;

#[async_trait]
impl Scenario for S043 {
    fn id(&self) -> &'static str {
        "S043"
    }
    fn description(&self) -> &'static str {
        "envelope aged ~20 blocks (inside PSO_PROOF_MAX_AGE) is admitted and executes"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

alloy::sol! {
    interface ITdViewS043 {
        function getData(uint256 tdId) external;
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let wallet = env.new_actor()?;
    let inner = Bytes::from(
        ITdViewS043::getDataCall {
            tdId: U256::from(1u64),
        }
        .abi_encode(),
    );

    // Pin the proof to the CURRENT head, then let the chain run ahead.
    let pinned = wallet
        .block_number()
        .await
        .map_err(|e| eyre::eyre!("head fetch: {e:?}"))?;

    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let head = wallet
            .block_number()
            .await
            .map_err(|e| eyre::eyre!("head poll: {e:?}"))?;
        if head >= pinned + AGE_BLOCKS {
            break;
        }
        if Instant::now() > deadline {
            return Err(eyre::eyre!(
                "S043: chain did not advance {AGE_BLOCKS} blocks within 120s \
                 (head {head}, pinned {pinned}) — is auto-mining on?"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let tx = wallet
        .submit_tx_pinned(TRIBUTE_DRAFT, inner, None, Some(pinned), |e| e)
        .await
        .map_err(|e| {
            eyre::eyre!("S043: aged-but-valid proof rejected (age ≈ {AGE_BLOCKS} blocks): {e:?}")
        })?;

    // Bonus assertion: it must also execute through the dispatcher.
    let receipt = wallet.wait_for_receipt(tx, Duration::from_secs(30)).await?;
    if !receipt.status() {
        return Err(eyre::eyre!(
            "S043: aged proof admitted but execution reverted (tx {tx:#x})"
        ));
    }
    tracing::info!(
        ?tx,
        age = AGE_BLOCKS,
        "S043: aged proof admitted and executed"
    );
    Ok(())
}
