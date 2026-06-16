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
//! - [`ActorClient::fetch_difficulty`] — `pso_vdfInfo` poll.
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
use pso_l2_client::contract_errors::{decode_from_bytes, decode_text, PsoContractError};

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

/// One-shot VDF proving parameters, as returned by `pso_vdfInfo` — mirrors
/// the node's `VdfStatus`. Carries everything an envelope build needs:
/// the difficulty to prove at and the head block to bind against.
#[derive(Debug, Clone, Copy)]
pub struct VdfInfo {
    /// Active-epoch VDF difficulty `T` — prove against this.
    pub current_difficulty: u64,
    /// Prior epoch's difficulty — accepted within the one-epoch boundary.
    pub previous_difficulty: u64,
    /// Current consensus epoch number.
    pub epoch: u64,
    /// Head L2 block — the VDF window upper bound (`submitted_block <= block`).
    pub block: u64,
}

impl ActorClient {
    /// Construct an actor-pool client.
    pub fn new(
        rpc_url: &str,
        chain_id: u64,
        secret_key: &[u8; 32],
    ) -> Result<Self, ActorClientError> {
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

    /// One-shot VDF proving parameters from `pso_vdfInfo`: the current +
    /// previous epoch difficulty, the consensus epoch, and the head block
    /// (the VDF window upper bound, `submitted_block <= block`). A single
    /// call replaces a separate difficulty poll *and* an `eth_blockNumber`
    /// round-trip — the node already returns the head here. (Replaces
    /// pso-chain's `pso_epochDifficulty`.)
    pub async fn fetch_vdf_info(&self) -> Result<VdfInfo, ActorClientError> {
        let resp = self.raw_json_rpc("pso_vdfInfo", json!([])).await?;
        let field = |name: &str| -> Result<u64, ActorClientError> {
            resp.get(name).and_then(Value::as_u64).ok_or_else(|| {
                ActorClientError::Transport(format!(
                    "pso_vdfInfo: missing/invalid '{name}' field in {resp}"
                ))
            })
        };
        Ok(VdfInfo {
            current_difficulty: field("current_difficulty")?,
            previous_difficulty: field("previous_difficulty")?,
            epoch: field("epoch")?,
            block: field("block")?,
        })
    }

    /// Convenience: just the current VDF difficulty (`fetch_vdf_info`'s
    /// `current_difficulty`).
    pub async fn fetch_difficulty(&self) -> Result<u64, ActorClientError> {
        Ok(self.fetch_vdf_info().await?.current_difficulty)
    }

    /// Fetch the current head block number. Prefer [`Self::fetch_vdf_info`]
    /// when the difficulty is also needed — it returns the head too, in one
    /// call.
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
        self.submit_tx_with_envelope(to, inner_calldata, |env| env)
            .await
    }

    /// Like [`Self::submit_tx`] but lets the caller mutate the
    /// already-built envelope bytes before signing.
    ///
    /// This is the scenario hook for the envelope-tampering tests
    /// (S013-S017): the closure receives the canonical 172-byte
    /// header + inner-calldata payload and returns whatever bytes
    /// should actually be signed and broadcast. The header layout
    /// is documented in [`crate::clients::envelope`].
    ///
    /// Returns whatever `eth_sendRawTransaction` answered with —
    /// either a pool-admission tx hash or a `PoolRejection` /
    /// `Revert` error decoded from the JSON-RPC body.
    pub async fn submit_tx_with_envelope<F>(
        &self,
        to: Address,
        inner_calldata: Bytes,
        mutate: F,
    ) -> Result<TxHash, ActorClientError>
    where
        F: FnOnce(Vec<u8>) -> Vec<u8>,
    {
        self.submit_tx_with_difficulty(to, inner_calldata, None, mutate)
            .await
    }

    /// Like [`Self::submit_tx_with_envelope`] but lets the caller
    /// pick a custom VDF iteration count `T` to compute the proof
    /// at. `None` falls back to `fetch_difficulty()` (canonical
    /// happy-path source — `pso_vdfInfo` against the chain's
    /// current epoch). `Some(t)` runs MinRoot at exactly `t`
    /// iterations.
    ///
    /// Useful for difficulty-mismatch scenarios (S031) — pass a
    /// value outside the chain's accepted `current ∪ previous`
    /// window and assert `PoolRejection`.
    pub async fn submit_tx_with_difficulty<F>(
        &self,
        to: Address,
        inner_calldata: Bytes,
        custom_difficulty: Option<u64>,
        mutate: F,
    ) -> Result<TxHash, ActorClientError>
    where
        F: FnOnce(Vec<u8>) -> Vec<u8>,
    {
        self.submit_tx_pinned(to, inner_calldata, custom_difficulty, None, mutate)
            .await
    }

    /// Like [`Self::submit_tx_with_difficulty`] but additionally lets
    /// the caller pin `submitted_block` instead of using the current
    /// head. The envelope's VDF binding is derived for the pinned
    /// block, so the proof is genuinely "as of" that height —
    /// admission then depends solely on the chain-side age window
    /// (`PSO_PROOF_MAX_AGE`). Used by the proof-aging scenario (S043)
    /// to model a slow wallet whose proof is several blocks old by
    /// the time it broadcasts.
    pub async fn submit_tx_pinned<F>(
        &self,
        to: Address,
        inner_calldata: Bytes,
        custom_difficulty: Option<u64>,
        pinned_block: Option<u64>,
        mutate: F,
    ) -> Result<TxHash, ActorClientError>
    where
        F: FnOnce(Vec<u8>) -> Vec<u8>,
    {
        // Resolve difficulty + head. When NEITHER is overridden, a single
        // pso_vdfInfo call supplies both (it returns the head block too) — no
        // separate eth_blockNumber round-trip. When one is pinned, fetch only
        // the other.
        let (difficulty, head) = match (custom_difficulty, pinned_block) {
            (Some(t), Some(b)) => (t, b),
            (Some(t), None) => (t, self.block_number().await?),
            (None, Some(b)) => (self.fetch_difficulty().await?, b),
            (None, None) => {
                let info = self.fetch_vdf_info().await?;
                (info.current_difficulty, info.block)
            }
        };
        let nonce = self.nonce().await?;

        let envelope = build_users_pool_calldata(
            self.address(),
            nonce,
            head,
            self.inner.chain_id,
            difficulty,
            &inner_calldata,
        )
        .map_err(|e| ActorClientError::Config(format!("envelope build: {e}")))?;
        let data = mutate(envelope);

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
        let s = resp.as_str().ok_or_else(|| {
            ActorClientError::Transport(format!(
                "eth_sendRawTransaction returned non-string: {resp}"
            ))
        })?;
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
        parsed.get("result").cloned().ok_or_else(|| {
            ActorClientError::Transport(format!("{method} missing 'result': {text}"))
        })
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
