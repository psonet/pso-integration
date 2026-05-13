//! Users-pool client (`:8546`).
//!
//! Speaks the same `eth_sendRawTransaction` shape as the standard
//! EL endpoint, but the calldata MUST be wrapped in the PSO Users
//! pool envelope (4B magic + 32B nullifier + 32B vdf_input + 48B
//! vdf_output + 48B vdf_proof + 8B submitted_block + inner). The
//! validator re-derives `vdf_input` from
//! `SHA-256(signer || nonce || submitted_block || chain_id)`, runs
//! MinRoot verify under the current epoch's `T`, and finally
//! dispatches the inner calldata through the EVM execution layer.
//!
//! Surface:
//!
//! - [`ActorClient::new`] — construct with rpc, chain id, secret key.
//! - [`ActorClient::fetch_difficulty`] — `pso_epochDifficulty` poll.
//! - [`ActorClient::submit_tx`] — fetch nonce + head + difficulty,
//!   wrap calldata, sign EIP-1559 with `max_fee = 0`, broadcast.
//! - [`ActorClient::wait_for_receipt`] — poll a tx hash to inclusion.
//!
//! Errors are surfaced as [`ActorClientError`]; the
//! `data`-bearing variants pump through `errors::decode_from_bytes`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2930::AccessList;
use alloy::network::TxSignerSync;
use alloy::primitives::{Address, Bytes, TxHash, TxKind, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::transports::http::reqwest::{Client as HttpClient, Url};
use serde_json::{json, Value};

use crate::clients::envelope::build_users_pool_calldata;
use crate::errors::{decode_from_bytes, decode_text, PsoContractError};

/// Users-pool client.
#[derive(Clone)]
pub struct ActorClient {
    inner: Arc<Inner>,
}

struct Inner {
    rpc_url: Url,
    chain_id: u64,
    signer: PrivateKeySigner,
}

/// Errors specific to the actor RPC path. Wraps the typed
/// [`PsoContractError`] under `Revert`, isolates JSON-RPC plumbing
/// failures into `Transport`, and exposes structured pool rejections
/// (the actor RPC returns `-32602` with the reason text inline).
#[derive(Debug)]
pub enum ActorClientError {
    /// Local config issue (bad URL, bad key).
    Config(String),
    /// HTTP / JSON-RPC transport failure (network down, malformed
    /// reply, etc.).
    Transport(String),
    /// Pool rejection — the magic gate, VDF binding, VDF verify,
    /// nullifier check, etc. all surface this way.
    PoolRejection(String),
    /// EVM revert with decoded selector / args.
    Revert(PsoContractError),
    /// Timed out waiting for a receipt.
    ReceiptTimeout,
}

impl std::fmt::Display for ActorClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActorClientError::Config(s) => write!(f, "actor config: {s}"),
            ActorClientError::Transport(s) => write!(f, "actor transport: {s}"),
            ActorClientError::PoolRejection(s) => write!(f, "actor pool rejection: {s}"),
            ActorClientError::Revert(e) => write!(f, "actor revert: {e}"),
            ActorClientError::ReceiptTimeout => write!(f, "actor receipt timeout"),
        }
    }
}

impl std::error::Error for ActorClientError {}

impl ActorClient {
    /// Construct an actor-pool client.
    pub fn new(rpc_url: &str, chain_id: u64, secret_key: &[u8; 32]) -> Result<Self, ActorClientError> {
        let url = rpc_url
            .parse::<Url>()
            .map_err(|e| ActorClientError::Config(format!("rpc url: {e}")))?;
        let signer = PrivateKeySigner::from_slice(secret_key)
            .map_err(|e| ActorClientError::Config(format!("secret key: {e}")))?
            .with_chain_id(Some(chain_id));
        Ok(Self {
            inner: Arc::new(Inner {
                rpc_url: url,
                chain_id,
                signer,
            }),
        })
    }

    /// EVM address of the attached signer.
    pub fn address(&self) -> Address {
        self.inner.signer.address()
    }

    /// Chain id passed at construction.
    pub fn chain_id(&self) -> u64 {
        self.inner.chain_id
    }

    /// Read-only `Provider` against the actor RPC. Used for
    /// `eth_getTransactionCount` / `eth_blockNumber` / receipt polls.
    pub fn provider(&self) -> impl Provider + Clone {
        ProviderBuilder::new().connect_http(self.inner.rpc_url.clone())
    }

    /// Call `pso_epochDifficulty()` on the actor RPC and parse the
    /// `difficulty` field out of the JSON response.
    pub async fn fetch_difficulty(&self) -> Result<u64, ActorClientError> {
        let resp = self.raw_json_rpc("pso_epochDifficulty", json!([])).await?;
        let diff = resp
            .get("difficulty")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ActorClientError::Transport(format!(
                "pso_epochDifficulty: missing/invalid 'difficulty' field in {resp}"
            )))?;
        Ok(diff)
    }

    /// Fetch the current head block number.
    pub async fn block_number(&self) -> Result<u64, ActorClientError> {
        self.provider()
            .get_block_number()
            .await
            .map_err(|e| ActorClientError::Transport(e.to_string()))
    }

    /// Fetch the signer's pending nonce.
    pub async fn nonce(&self) -> Result<u64, ActorClientError> {
        self.provider()
            .get_transaction_count(self.address())
            .pending()
            .await
            .map_err(|e| ActorClientError::Transport(e.to_string()))
    }

    /// End-to-end happy path: fetch difficulty + nonce + head, wrap
    /// `inner_calldata` in a PSO Users-pool envelope, build & sign a
    /// gas-free EIP-1559 tx, broadcast via `eth_sendRawTransaction`.
    ///
    /// Returns the transaction hash on pool admission. Pool-level
    /// rejections (`-32602`) come back as `Err(PoolRejection)`;
    /// EVM-side reverts surface after `wait_for_receipt`.
    pub async fn submit_tx(
        &self,
        to: Address,
        inner_calldata: Bytes,
    ) -> Result<TxHash, ActorClientError> {
        let difficulty = self.fetch_difficulty().await?;
        let head = self.block_number().await?;
        let nonce = self.nonce().await?;

        let data = build_users_pool_calldata(
            self.address(),
            nonce,
            head,
            self.inner.chain_id,
            difficulty,
            &inner_calldata,
        )
        .map_err(|e| ActorClientError::Config(format!("envelope build: {e}")))?;

        // EIP-1559 envelope with both gas fields zeroed — pso-chain's
        // actor RPC accepts only `max_fee = max_priority_fee = 0`
        // for users-pool transactions.
        let mut tx = TxEip1559 {
            chain_id: self.inner.chain_id,
            nonce,
            gas_limit: 5_000_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(to),
            value: U256::ZERO,
            access_list: AccessList::default(),
            input: data.into(),
        };

        // Sign synchronously — `PrivateKeySigner` implements both
        // sync and async variants and the sync path keeps the
        // tx-build call site flat.
        let signature = self
            .inner
            .signer
            .sign_transaction_sync(&mut tx)
            .map_err(|e| ActorClientError::Config(format!("sign: {e}")))?;
        let signed = tx.into_signed(signature);
        let envelope: TxEnvelope = signed.into();

        // Encode the EIP-2718 typed-tx wrapper for the wire.
        let mut raw = Vec::with_capacity(256);
        alloy::eips::eip2718::Encodable2718::encode_2718(&envelope, &mut raw);
        let raw_hex = format!("0x{}", hex::encode(&raw));

        let resp = self
            .raw_json_rpc("eth_sendRawTransaction", json!([raw_hex]))
            .await?;
        let s = resp
            .as_str()
            .ok_or_else(|| ActorClientError::Transport(format!(
                "eth_sendRawTransaction returned non-string: {resp}"
            )))?;
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| ActorClientError::Transport(format!("tx-hash hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(ActorClientError::Transport(format!(
                "tx hash wrong length: {}",
                bytes.len()
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(TxHash::from(hash))
    }

    /// Poll a tx hash to inclusion. Returns the receipt on success
    /// (status flag may be 0 — caller decides what that means for
    /// the scenario).
    pub async fn wait_for_receipt(
        &self,
        tx: TxHash,
        timeout: Duration,
    ) -> Result<TransactionReceipt, ActorClientError> {
        let provider = self.provider();
        let deadline = Instant::now() + timeout;
        loop {
            match provider.get_transaction_receipt(tx).await {
                Ok(Some(r)) => return Ok(r),
                Ok(None) => {}
                Err(e) => return Err(ActorClientError::Transport(e.to_string())),
            }
            if Instant::now() >= deadline {
                return Err(ActorClientError::ReceiptTimeout);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    // -----------------------------------------------------------------
    // Internal JSON-RPC plumbing.
    // -----------------------------------------------------------------

    /// Hand-rolled JSON-RPC POST. Goes around alloy's typed surface
    /// because we (a) need access to `data` bytes on errors and (b)
    /// already encode the raw tx ourselves.
    async fn raw_json_rpc(&self, method: &str, params: Value) -> Result<Value, ActorClientError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id":      1,
            "method":  method,
            "params":  params,
        });
        let client = HttpClient::new();
        let resp = client
            .post(self.inner.rpc_url.clone())
            .json(&body)
            .send()
            .await
            .map_err(|e| ActorClientError::Transport(format!("post {method}: {e}")))?;
        let text = resp
            .text()
            .await
            .map_err(|e| ActorClientError::Transport(format!("read {method}: {e}")))?;
        let parsed: Value = serde_json::from_str(&text).map_err(|e| {
            ActorClientError::Transport(format!("parse {method} response '{text}': {e}"))
        })?;

        if let Some(err) = parsed.get("error") {
            return Err(json_rpc_error_to_typed(err));
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| ActorClientError::Transport(format!("{method} missing 'result': {text}")))
    }
}

/// Turn the JSON-RPC `error` object into the right typed variant.
///
/// pso-chain's actor RPC uses `-32602 (invalid_params)` for every
/// pool-side rejection (magic gate, VDF binding, stale proof,
/// nullifier collision, ...). EVM-side reverts come back as `-32603`
/// (internal error) or `3` (Geth-style execution-reverted) with hex
/// `data` carrying the custom-error selector + args.
fn json_rpc_error_to_typed(err: &Value) -> ActorClientError {
    let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
    let msg = err
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let data_hex = err
        .get("data")
        .and_then(|d| d.as_str())
        .map(|s| s.to_string());

    if let Some(hex_s) = data_hex {
        let stripped = hex_s.trim_start_matches("0x");
        if let Ok(bytes) = hex::decode(stripped) {
            return ActorClientError::Revert(decode_from_bytes(&bytes));
        }
    }

    // No structured data — classify by message + code.
    match code {
        -32602 => ActorClientError::PoolRejection(msg),
        _ => {
            // Best-effort textual decode (covers `MethodNotPermitted`
            // dumps that appear in pool messages).
            ActorClientError::Revert(decode_text(&msg))
        }
    }
}
