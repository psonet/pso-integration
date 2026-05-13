//! Agents-pool client.
//!
//! Wraps a signing [`L2Client`] pointed at the standard EL JSON-RPC
//! (`:19545`) and re-exports the existing `pso-l2-client::sra` flow
//! functions as methods. The pool validator admits a tx iff
//!
//! - `from` is in `SRARegistry` (`isActive(sender) == true`), AND
//! - `(to, selector)` is in the agents-pool allowlist
//!   (`SR.submit`, `AR.submit`, `SU.submit`).
//!
//! `TD.submit` is NOT in the allowlist on purpose — the wallet path
//! goes through the actor pool. S002 asserts this.

use std::time::{Duration, Instant};

use alloy::primitives::{Address, FixedBytes, TxHash, U256};
use alloy::providers::Provider;

use pso_l2_client::abi::{ISpendingRecord, ISpendingRecordAmendment, ISpendingUnit};
use pso_l2_client::{sra, L2Client, L2ClientError};

use crate::errors::PsoContractError;

/// Agents-pool RPC client. Cheap to clone (`L2Client` is `Arc`-backed).
#[derive(Clone)]
pub struct SraClient {
    /// Underlying alloy + signer handle. Exposed via accessors when a
    /// caller needs to drop down to read-only Provider operations.
    inner: L2Client,
    rpc_url: String,
}

impl SraClient {
    /// Build from an RPC URL, chain id, and a 32-byte secp256k1 secret
    /// key. The signer is gas-free — every helper here pins
    /// `max_fee_per_gas = max_priority_fee_per_gas = 0` via the
    /// underlying `pso-l2-client::sra` functions.
    pub fn new(rpc_url: &str, chain_id: u64, secret_key: &[u8; 32]) -> eyre::Result<Self> {
        let inner = L2Client::connect_with_signer(rpc_url, chain_id, secret_key)
            .map_err(|e| eyre::eyre!("SraClient connect: {e}"))?;
        Ok(Self {
            inner,
            rpc_url: rpc_url.to_string(),
        })
    }

    /// Underlying `L2Client`. Use when calling a `pso-l2-client::*`
    /// free function that takes `&L2Client`.
    pub fn inner(&self) -> &L2Client {
        &self.inner
    }

    /// RPC URL this client was built against — handy for spawning a
    /// fresh read-only `L2Client` for tx-wait polling.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// EVM address of the attached signer.
    pub fn address(&self) -> Address {
        self.inner.signer_address().expect("signer attached")
    }

    /// Configured chain id.
    pub fn chain_id(&self) -> u64 {
        self.inner.chain_id()
    }

    // -----------------------------------------------------------------
    // Flow methods — thin re-exports of `pso-l2-client::sra::*` keyed
    // off `self.inner`. Returning `L2ClientError` keeps the helper
    // surface honest; scenarios map into `PsoContractError` via
    // `into_pso_error`.
    // -----------------------------------------------------------------

    /// `SpendingRecord.submit(srId, keys, values)`.
    pub async fn register_spending_record(
        &self,
        sr_id: U256,
        keys: Vec<String>,
        values: Vec<FixedBytes<32>>,
    ) -> Result<TxHash, L2ClientError> {
        sra::register_spending_record(&self.inner, sr_id, keys, values).await
    }

    /// `SpendingRecordAmendment.submit(...)`.
    pub async fn register_amendment_record(
        &self,
        ar_id: U256,
        keys: Vec<String>,
        values: Vec<FixedBytes<32>>,
    ) -> Result<TxHash, L2ClientError> {
        sra::register_amendment_record(&self.inner, ar_id, keys, values).await
    }

    /// `SpendingUnit.submit(...)`.
    pub async fn mint_spending_unit(
        &self,
        args: sra::MintSpendingUnitArgs,
    ) -> Result<TxHash, L2ClientError> {
        sra::mint_spending_unit(&self.inner, args).await
    }

    // -----------------------------------------------------------------
    // Wait helpers (migrated from the old `tests/full_flow.rs`).
    // -----------------------------------------------------------------

    /// Poll `eth_getTransactionReceipt(tx)` until success/failure or
    /// `timeout` elapses. Returns an error if the receipt's status
    /// flag is `false` (EVM revert) or if no receipt arrived in time.
    pub async fn wait_for_tx_success(&self, tx: TxHash, timeout: Duration) -> eyre::Result<()> {
        let provider = self.inner.read_provider();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(receipt) = provider.get_transaction_receipt(tx).await? {
                if receipt.status() {
                    return Ok(());
                }
                return Err(eyre::eyre!("tx {tx:#x} reverted on-chain"));
            }
            if Instant::now() >= deadline {
                return Err(eyre::eyre!("timeout: no receipt for {tx:#x}"));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Wait until every passed SR/AR id is observable via the SBT
    /// `exists(uint256)` view on the predeployed registries. Used
    /// after `register_spending_record` so the downstream SU mint
    /// pre-flight (which calls `exists(h)` against head state) does
    /// not race the inclusion of the records.
    pub async fn wait_for_sr_existence(
        &self,
        sr_ids: &[U256],
        ar_ids: &[U256],
        timeout: Duration,
    ) -> eyre::Result<()> {
        let provider = self.inner.read_provider();
        let sr = ISpendingRecord::new(pso_l2_client::abi::SPENDING_RECORD, &provider);
        let ar =
            ISpendingRecordAmendment::new(pso_l2_client::abi::SPENDING_RECORD_AMENDMENT, &provider);
        let deadline = Instant::now() + timeout;
        let mut last_missing: Option<U256> = None;
        loop {
            let mut all = true;
            for id in sr_ids {
                if !sr_exists(&sr, *id).await? {
                    all = false;
                    last_missing = Some(*id);
                    break;
                }
            }
            if all {
                for id in ar_ids {
                    if !ar_exists(&ar, *id).await? {
                        all = false;
                        last_missing = Some(*id);
                        break;
                    }
                }
            }
            if all {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(eyre::eyre!(
                    "timeout: SR/AR ids not visible on-chain after {:?}, last_missing={:?}",
                    timeout,
                    last_missing
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Wait until every passed SU id is observable via
    /// `SpendingUnit.exists(uint256)`. Used before `TributeDraft.submit`
    /// so the contract's `getData(suId)` lookup sees the freshly
    /// minted SUs.
    pub async fn wait_for_su_existence(
        &self,
        su_ids: &[U256],
        timeout: Duration,
    ) -> eyre::Result<()> {
        let provider = self.inner.read_provider();
        let su = ISpendingUnit::new(pso_l2_client::abi::SPENDING_UNIT, &provider);
        let deadline = Instant::now() + timeout;
        loop {
            let mut all = true;
            for id in su_ids {
                if !su_exists(&su, *id).await? {
                    all = false;
                    break;
                }
            }
            if all {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(eyre::eyre!(
                    "timeout: SU ids not visible on-chain after {:?}",
                    timeout
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// Convert an `L2ClientError` (contract-call wrapper around alloy) into
/// a typed `PsoContractError`. Used by every scenario assertion path:
/// `let err = sra.call().await.map_err(into_pso_error);`.
pub fn into_pso_error(err: L2ClientError) -> PsoContractError {
    // `L2ClientError::Contract(String)` wraps the alloy error's
    // Display output. We pump the same string through the textual
    // path of `errors::decode_from_bytes` via `decode_revert_text`.
    match err {
        L2ClientError::Contract(s) => decode_revert_text(&s),
        other => PsoContractError::Other(other.to_string()),
    }
}

/// Decode a textual alloy error message into the typed enum. The
/// underlying primitive is `errors::decode_from_bytes` plus the
/// hex-extraction helper exposed via `errors::decode` for free
/// functions; here we go directly because we already have the text.
fn decode_revert_text(msg: &str) -> PsoContractError {
    // Re-uses the same hex-extraction logic as `errors::decode`, but
    // we cannot call it directly without an `alloy::contract::Error`.
    // Build a synthetic Display-equivalent string and round-trip.
    crate::errors::decode_text(msg)
}

// =====================================================================
// Inline ABI views — `exists(uint256)` isn't on the standard interface
// declared in pso-l2-client; mirror it here so we can wait on it.
// =====================================================================

alloy::sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IExistsLike {
        function exists(uint256 tokenId) external view returns (bool);
    }
}

async fn sr_exists<P: Provider + Clone>(
    sr: &ISpendingRecord::ISpendingRecordInstance<&P>,
    id: U256,
) -> eyre::Result<bool> {
    // We don't have `exists` in `ISpendingRecord`; reinterpret the
    // contract through the local `IExistsLike` view at the same
    // address.
    let provider = sr.provider();
    let view = IExistsLike::new(*sr.address(), provider);
    Ok(view.exists(id).call().await?)
}

async fn ar_exists<P: Provider + Clone>(
    ar: &ISpendingRecordAmendment::ISpendingRecordAmendmentInstance<&P>,
    id: U256,
) -> eyre::Result<bool> {
    let provider = ar.provider();
    let view = IExistsLike::new(*ar.address(), provider);
    Ok(view.exists(id).call().await?)
}

async fn su_exists<P: Provider + Clone>(
    su: &ISpendingUnit::ISpendingUnitInstance<&P>,
    id: U256,
) -> eyre::Result<bool> {
    let provider = su.provider();
    let view = IExistsLike::new(*su.address(), provider);
    Ok(view.exists(id).call().await?)
}
