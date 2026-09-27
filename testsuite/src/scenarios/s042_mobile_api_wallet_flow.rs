//! S042 — wallet simulator built from the MOBILE API, end-to-end
//! through the envelope dispatcher.
//!
//! Every other envelope scenario goes through the testsuite's own
//! builders (`clients/envelope.rs` + `ActorClient`). Real wallets
//! don't: they call `pso-mobile-integration`'s UniFFI surface and
//! assemble the transaction from there. That divergence is exactly
//! where wallet-only bugs hide (e.g. the gasLimit=1000 intrinsic-gas
//! bug that CI never saw).
//!
//! This scenario plays the mobile wallet, using NOTHING from the
//! testsuite's envelope machinery:
//!
//! 1. Binding + solution via `pso_mobile_integration::{derive_vdf_input,
//!    solve_pow}` (the same code the UniFFI bindings wrap), sanity-checked
//!    with `verify_pow` before broadcast.
//! 2. Inner EIP-1559 tx (clean calldata) signed with gasLimit = 5M and
//!    zero fee caps, then wrapped by the mobile API's own
//!    `build_pow_envelope` — the one encoder the wallet, the bindings and
//!    this scenario share, so the wire layout cannot drift between them.
//! 3. Broadcast via raw JSON-RPC `eth_sendRawTransaction` against the
//!    actor RPC.
//!
//! The inner calldata is `TributeDraft.getData(7)` — a benign call
//! that MUST execute with `status == 1`, which proves the full
//! execution path: pool admission (VDF/nullifier/age) → block
//! inclusion → `PsoEnvelopeDispatcher` fallback strips the 172-byte
//! header → inner dispatch succeeds.

use std::time::{Duration, Instant};

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2930::AccessList;
use alloy_network::TxSignerSync;
use alloy_primitives::{Bytes, TxKind, U256};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use alloy_transport_http::reqwest::{Client as HttpClient, Url};
use async_trait::async_trait;
use rand::Rng;
use serde_json::{json, Value};

use pso_chain_abi::addresses::TRIBUTE_DRAFT;

use crate::{Scenario, TestEnv};

pub struct S042;

#[async_trait]
impl Scenario for S042 {
    fn id(&self) -> &'static str {
        "S042"
    }
    fn description(&self) -> &'static str {
        "mobile-API wallet flow: uniffi VDF + self-assembled envelope tx executes (status=1)"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

alloy_sol_types::sol! {
    /// Benign inner call — selector only; return data is ignored.
    interface ITdViewS042 {
        function getData(uint256 tdId) external;
    }
}

/// Minimal JSON-RPC helper — deliberately NOT `ActorClient`.
async fn rpc(url: &Url, method: &str, params: Value) -> eyre::Result<Value> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let resp: Value = HttpClient::new()
        .post(url.clone())
        .json(&body)
        .send()
        .await?
        .json()
        .await?;
    if let Some(err) = resp.get("error") {
        return Err(eyre::eyre!("{method} error: {err}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| eyre::eyre!("{method}: no result"))
}

fn hex_u64(v: &Value) -> eyre::Result<u64> {
    let s = v
        .as_str()
        .ok_or_else(|| eyre::eyre!("expected hex string"))?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let url: Url = env.actor_rpc_url.parse()?;

    // Fresh wallet identity — never registered anywhere, no balance
    // (the users lane is feeless).
    let mut sk = [0u8; 32];
    rand::rng().fill_bytes(&mut sk);
    let signer = PrivateKeySigner::from_slice(&sk)?.with_chain_id(Some(env.chain_id));
    let wallet_addr = signer.address();

    // 1. Chain context straight off the actor RPC (the only endpoint a real
    //    wallet talks to). One pso_vdfInfo call carries BOTH the difficulty to
    //    prove at and the head block to bind against — no separate
    //    eth_blockNumber round-trip.
    let vdf_info = rpc(&url, "pso_vdfInfo", json!([])).await?;
    let difficulty = vdf_info
        .get("current_difficulty")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre::eyre!("pso_vdfInfo: no current_difficulty"))?;
    let head = vdf_info
        .get("block")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre::eyre!("pso_vdfInfo: no block"))?;
    let nonce = hex_u64(
        &rpc(
            &url,
            "eth_getTransactionCount",
            json!([wallet_addr, "pending"]),
        )
        .await?,
    )?;

    // 2. Anti-spam work through the MOBILE API — the exact `Wallet` methods
    //    the UniFFI bindings export to React Native. The wallet checks its own
    //    solution before spending a broadcast on it.
    let mobile = pso_mobile_integration::Wallet::new(env.chain_id);
    let binding = mobile
        .derive_vdf_input(wallet_addr.0 .0.to_vec(), nonce, head)
        .map_err(|e| eyre::eyre!("mobile derive_vdf_input: {e:?}"))?;
    let pow = mobile
        .solve_pow(binding.clone(), difficulty)
        .map_err(|e| eyre::eyre!("mobile solve_pow: {e:?}"))?;
    let verified = mobile
        .verify_pow(binding, pow.solution.clone(), pow.scheme, difficulty)
        .map_err(|e| eyre::eyre!("mobile verify_pow: {e:?}"))?;
    if !verified {
        return Err(eyre::eyre!(
            "S042: mobile verify_pow failed on its own solution"
        ));
    }

    let inner = ITdViewS042::getDataCall {
        tdId: U256::from(7u64),
    }
    .abi_encode();

    // 3. Build & sign the INNER tx with CLEAN calldata. The anti-spam fields
    //    ride the wire envelope, not the calldata. gasLimit 5M; zero fee caps
    //    for the feeless lane.
    let mut tx = TxEip1559 {
        chain_id: env.chain_id,
        nonce,
        gas_limit: 5_000_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(TRIBUTE_DRAFT),
        value: U256::ZERO,
        access_list: AccessList::default(),
        input: Bytes::from(inner),
    };
    let sig = signer.sign_transaction_sync(&mut tx)?;
    let inner_envelope: TxEnvelope = tx.into_signed(sig).into();
    let mut inner_2718 = Vec::with_capacity(512);
    alloy_eips::eip2718::Encodable2718::encode_2718(&inner_envelope, &mut inner_2718);

    // 4. Wrap the inner 2718 bytes through the mobile API's own encoder. It
    //    solves its own proof and derives its own nullifier from the seed, which
    //    is what a wallet actually calls — the sanity leg above is the wallet
    //    checking the work it can do, not a value this consumes.
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let raw = mobile
        .build_pow_envelope(
            seed.to_vec(),
            wallet_addr.0 .0.to_vec(),
            nonce,
            head,
            difficulty,
            inner_2718,
        )
        .map_err(|e| eyre::eyre!("mobile build_pow_envelope: {e:?}"))?;

    let tx_hash = rpc(
        &url,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&raw))]),
    )
    .await
    .map_err(|e| eyre::eyre!("S042: wallet tx rejected at admission: {e}"))?;

    // 5. The tx must EXECUTE, not just admit: status == 1 proves the
    //    envelope dispatcher stripped the header and dispatched the
    //    inner call.
    //
    // Generous deadline: a lone users-lane tx is only mined on the next block
    // tick, and a `--dev` node produces blocks burstily when otherwise idle
    // (measured ~16s gaps between empty blocks vs ~1s under load). Inclusion
    // latency is therefore bimodal — usually ~1s, but up to ~tens of seconds if
    // the tx lands in an idle gap. The proof stays valid for PSO_PROOF_MAX_AGE
    // blocks regardless; we just need to wait long enough to observe inclusion.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let receipt = rpc(&url, "eth_getTransactionReceipt", json!([tx_hash])).await?;
        if !receipt.is_null() {
            let status = receipt
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("0x0");
            if status == "0x1" {
                tracing::info!(
                    ?tx_hash,
                    sender = ?wallet_addr,
                    "S042: mobile-API wallet tx executed through the dispatcher"
                );
                return Ok(());
            }
            return Err(eyre::eyre!(
                "S042: wallet tx mined but reverted (status {status}) — \
                 envelope dispatcher did not strip/dispatch (tx {tx_hash})"
            ));
        }
        if Instant::now() > deadline {
            return Err(eyre::eyre!("S042: receipt timeout for {tx_hash}"));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
