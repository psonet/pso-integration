//! S045 — the chain posts a consensus-verified DA batch to L1.
//!
//! Positive coverage of the verifiable batched data-availability path:
//! the BFT chain finalizes a rotation epoch's blocks and posts them to
//! the `DaInbox` settlement contract on L1, together with the epoch's
//! BLS threshold finalization certificate. The contract verifies that
//! certificate against the chain's group public key before recording
//! the commitment — so reading `hasCommitment() == true` on L1 means a
//! batch was finalized by 2f+1 of the attester set and settled, the
//! property OP's batch inbox can't prove on-chain. This replaces the
//! standalone `mise run test:da-e2e` smoke test: the whole chain — L2
//! invariants AND DA settlement — is now one suite.
//!
//! Wiring: needs `--l1-rpc-url` + `--da-inbox` (the harness that brings
//! up the devnet deploys the inbox and passes its address). When those
//! aren't supplied the scenario is filtered out in `main` rather than
//! run — so consumers that don't expose their L1 to the suite are
//! unaffected.

use std::time::{Duration, Instant};

use alloy::providers::ProviderBuilder;
use alloy::sol;
use alloy::transports::http::reqwest::Url;
use async_trait::async_trait;

use crate::{Scenario, TestEnv};

sol! {
    #[sol(rpc)]
    interface IDaInbox {
        function hasCommitment() external view returns (bool);
        function lastEpoch() external view returns (uint64);
    }
}

/// How long to wait for the first batch to settle. By the time S045
/// runs the chain has been up through the rest of the suite, so a
/// commitment is normally already present; the budget covers a cold
/// start (one epoch must finalize and post).
const COMMIT_TIMEOUT: Duration = Duration::from_secs(180);

pub struct S045;

#[async_trait]
impl Scenario for S045 {
    fn id(&self) -> &'static str {
        "S045"
    }
    fn description(&self) -> &'static str {
        "chain posts a consensus-verified DA batch to the L1 DaInbox"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // main() only schedules S045 when both are set, but assert rather
    // than silently pass so a wiring mistake surfaces as a failure.
    let l1_url = env
        .l1_rpc_url
        .as_deref()
        .ok_or_else(|| eyre::eyre!("S045 requires --l1-rpc-url"))?;
    let inbox_addr = env
        .da_inbox
        .ok_or_else(|| eyre::eyre!("S045 requires --da-inbox"))?;

    let url: Url = l1_url
        .parse()
        .map_err(|e| eyre::eyre!("invalid --l1-rpc-url {l1_url}: {e}"))?;
    let provider = ProviderBuilder::new().connect_http(url);
    let inbox = IDaInbox::new(inbox_addr, &provider);

    let deadline = Instant::now() + COMMIT_TIMEOUT;
    loop {
        // A transient L1 RPC hiccup shouldn't fail the scenario; only a
        // genuine timeout does. Treat a failed read as "not yet".
        let committed = inbox.hasCommitment().call().await.unwrap_or(false);
        if committed {
            let epoch = inbox
                .lastEpoch()
                .call()
                .await
                .map_err(|e| eyre::eyre!("DaInbox.lastEpoch: {e}"))?;
            tracing::info!(inbox = %inbox_addr, epoch, "DA batch committed on L1");
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "S045: no DA batch committed to DaInbox {inbox_addr} within {}s",
                COMMIT_TIMEOUT.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
