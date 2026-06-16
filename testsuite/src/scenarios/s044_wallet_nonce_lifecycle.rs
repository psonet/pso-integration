//! S044 — wallet account lifecycle across nonces.
//!
//! A real wallet sends tx after tx. The VDF binding bakes the tx
//! nonce into the input (`SHA-256(signer || nonce || block || chain)`),
//! so every transaction needs a freshly computed proof, and a proof
//! computed for nonce N is dead the moment nonce N is consumed.
//!
//! Three legs:
//!
//! 1. tx@nonce0 — canonical envelope → admitted AND executed.
//! 2. tx@nonce1 — fresh envelope (VDF recomputed for nonce 1) →
//!    admitted AND executed. Pins "sequential submission just works".
//! 3. tx@nonce2 carrying tx@nonce0's VDF section (input‖output‖proof
//!    bytes [36..164) verbatim) — the "wallet reused a stale proof
//!    after a nonce bump" failure mode → MUST be rejected with
//!    `BadVdfInputBinding` BEFORE the (expensive) VDF verify runs.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::primitives::{Bytes, U256};
use alloy::sol_types::SolCall;
use async_trait::async_trait;

use pso_l2_client::abi::TRIBUTE_DRAFT;

use crate::clients::actor::ActorClientError;
use crate::{Scenario, TestEnv};

pub struct S044;

#[async_trait]
impl Scenario for S044 {
    fn id(&self) -> &'static str {
        "S044"
    }
    fn description(&self) -> &'static str {
        "sequential wallet txs (nonce 0,1) execute; stale VDF binding at nonce 2 rejected"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

alloy::sol! {
    interface ITdViewS044 {
        function getData(uint256 tdId) external;
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let wallet = env.new_actor()?;
    let inner = |id: u64| {
        Bytes::from(
            ITdViewS044::getDataCall {
                tdId: U256::from(id),
            }
            .abi_encode(),
        )
    };

    // Leg 1 — nonce 0, capture the envelope's VDF binding section
    // (vdf_input ‖ len‖output ‖ len‖proof; the 0x76 wire VDF_BINDING_RANGE)
    // for leg 3.
    let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let cap = captured.clone();
    let tx0 = wallet
        .submit_tx_with_envelope(TRIBUTE_DRAFT, inner(1), move |bytes| {
            *cap.lock().expect("vdf capture") =
                Some(bytes[crate::clients::envelope::VDF_BINDING_RANGE].to_vec());
            bytes
        })
        .await
        .map_err(|e| eyre::eyre!("S044 leg1 (nonce 0): {e:?}"))?;
    let r0 = wallet
        .wait_for_receipt(tx0, Duration::from_secs(120))
        .await?;
    if !r0.status() {
        return Err(eyre::eyre!("S044 leg1 reverted (tx {tx0:#x})"));
    }

    // Leg 2 — nonce 1, fresh VDF. The client recomputes the binding
    // for the new nonce exactly like a wallet must.
    let tx1 = wallet
        .submit_tx(TRIBUTE_DRAFT, inner(2))
        .await
        .map_err(|e| eyre::eyre!("S044 leg2 (nonce 1): {e:?}"))?;
    let r1 = wallet
        .wait_for_receipt(tx1, Duration::from_secs(120))
        .await?;
    if !r1.status() {
        return Err(eyre::eyre!("S044 leg2 reverted (tx {tx1:#x})"));
    }

    // Leg 3 — nonce 2, but splice in leg 1's VDF section. The
    // validator re-derives the expected input from (signer, nonce=2,
    // block, chain) and must reject the nonce-0 binding.
    let stale = captured
        .lock()
        .expect("vdf capture")
        .clone()
        .ok_or_else(|| eyre::eyre!("S044: leg1 capture missing"))?;
    let result = wallet
        .submit_tx_with_envelope(TRIBUTE_DRAFT, inner(3), move |mut bytes| {
            bytes[crate::clients::envelope::VDF_BINDING_RANGE].copy_from_slice(&stale);
            bytes
        })
        .await;

    match result {
        Err(ActorClientError::PoolRejection(msg)) if msg.contains("BadVdfInputBinding") => {
            tracing::info!(%msg, "S044: stale nonce binding rejected as expected");
            Ok(())
        }
        Err(other) => Err(eyre::eyre!(
            "S044 leg3: expected BadVdfInputBinding, got {other:?}"
        )),
        Ok(tx) => Err(eyre::eyre!(
            "S044 leg3: stale nonce-0 VDF binding was ADMITTED at nonce 2 (tx {tx:?}) — \
             replayed proofs must not survive a nonce bump"
        )),
    }
}
