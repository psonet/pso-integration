//! Agents-pool client.
//!
//! Wraps a signing [`RpcHandle`] pointed at the standard EL JSON-RPC
//! (`:19545`) and exposes the SRA flow functions (SR/AR/SU submit) as
//! methods, built directly on the `pso-chain-abi` interfaces. The pool
//! validator admits a tx iff
//!
//! - `from` is in `AttestersRegistry` (`isActive(sender) == true`), AND
//! - `(to, selector)` is in the agents-pool allowlist
//!   (`SR.submit`, `AR.submit`, `SU.submit`).
//!
//! `TD.submit` is NOT in the allowlist on purpose — the wallet path
//! goes through the actor pool. S002 asserts this.

use std::time::{Duration, Instant};

use alloy_primitives::{Address, FixedBytes, TxHash, U256};
use alloy_provider::Provider;

use pso_chain_abi::addresses::{AMENDMENT_RECORD, SPENDING_RECORD, SPENDING_UNIT};
use pso_chain_abi::interfaces::{IAmendmentRecord, ISpendingRecord, ISpendingUnit};

use crate::clients::rpc::{RpcError, RpcHandle};

/// All fields for `SpendingUnit.submit`. Bundled into a struct so the
/// CLI's 8 args don't degrade into positional spaghetti.
#[derive(Debug, Clone)]
pub struct MintSpendingUnitArgs {
    /// SU id (uint256). Random — the wallet must store this off-chain
    /// so it can later reference the SU when assembling a TributeDraft.
    pub su_id: U256,
    /// Wallet-supplied Poseidon ownership commitment for this SU.
    pub derived_owner: FixedBytes<32>,
    /// Wallet self-address captured at consent initiation. The SRA holds
    /// it for the consent session and stamps every SU minted in that
    /// session with it (the on-chain `referrerAddress`). `Address::ZERO`
    /// means "no referrer". TributeDraft aggregation later collects the
    /// deduplicated referrer set from the SUs.
    pub referrer_address: Address,
    /// ISO 4217 numeric currency code.
    pub currency: u16,
    /// Worldwide-day count (days since 2021-01-01) — `uint32` slot.
    pub worldwide_day: u32,
    /// Amount integer part.
    pub amount_base: u64,
    /// Amount fractional part (atto). On-chain the SU stores this in a
    /// `uint64` slot (atto < 1e18 always fits); we keep the wider
    /// `u128` here for caller convenience and narrow at submit time.
    pub amount_atto: u128,
    /// Spending record IDs included in this SU.
    pub sr_ids: Vec<U256>,
    /// Amendment-record IDs.
    pub amendment_sr_ids: Vec<U256>,
}

/// Agents-pool RPC client. Cheap to clone ([`RpcHandle`] is `Arc`-backed).
#[derive(Clone)]
pub struct SraClient {
    /// Underlying alloy + signer handle. Exposed via accessors when a
    /// caller needs to drop down to read-only Provider operations.
    inner: RpcHandle,
    rpc_url: String,
}

impl SraClient {
    /// Build from an RPC URL, chain id, and a 32-byte secp256k1 secret
    /// key. The signer is gas-free — every helper here pins
    /// `max_fee_per_gas = max_priority_fee_per_gas = 0`.
    pub fn new(rpc_url: &str, chain_id: u64, secret_key: &[u8; 32]) -> eyre::Result<Self> {
        let inner = RpcHandle::connect_with_signer(rpc_url, chain_id, secret_key)
            .map_err(|e| eyre::eyre!("SraClient connect: {e}"))?;
        Ok(Self {
            inner,
            rpc_url: rpc_url.to_string(),
        })
    }

    /// Underlying [`RpcHandle`]. Use when a scenario needs to drop down
    /// to a raw `Provider` (read-only state, custom calldata).
    pub fn inner(&self) -> &RpcHandle {
        &self.inner
    }

    /// RPC URL this client was built against — handy for spawning a
    /// fresh read-only handle for tx-wait polling.
    #[allow(dead_code)]
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
    // Flow methods — direct alloy `.submit(...)` calls on the
    // `pso-chain-abi` interfaces. Returning `RpcError` keeps the helper
    // surface honest; scenarios map into `PsoContractError` via
    // `into_pso_error`.
    // -----------------------------------------------------------------

    /// `SpendingRecord.submit(srId)`.
    pub async fn register_spending_record(&self, sr_id: U256) -> Result<TxHash, RpcError> {
        let provider = self.inner.write_provider()?;
        let inst = ISpendingRecord::new(SPENDING_RECORD, provider);
        let pending = inst
            .submit(sr_id)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| RpcError::Contract(format!("SR submit: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `AmendmentRecord.submit(arId)`.
    pub async fn register_amendment_record(&self, ar_id: U256) -> Result<TxHash, RpcError> {
        let provider = self.inner.write_provider()?;
        let inst = IAmendmentRecord::new(AMENDMENT_RECORD, provider);
        let pending = inst
            .submit(ar_id)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| RpcError::Contract(format!("AR submit: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `SpendingUnit.submit(...)`. The SRA is the on-chain submitter;
    /// the wallet supplied the `derivedOwner` commitment off-line so the
    /// chain can later verify a ZK ownership proof against it.
    pub async fn mint_spending_unit(
        &self,
        args: MintSpendingUnitArgs,
    ) -> Result<TxHash, RpcError> {
        let provider = self.inner.write_provider()?;
        let inst = ISpendingUnit::new(SPENDING_UNIT, provider);
        let pending = inst
            .submit(
                args.su_id,
                args.derived_owner,
                // `referrerAddress` — the wallet self-address from the consent
                // session (`Address::ZERO` if none).
                args.referrer_address,
                args.currency,
                args.worldwide_day,
                args.amount_base,
                // SU stores atto in a `uint64` slot; atto < 1e18 always fits.
                args.amount_atto as u64,
                args.sr_ids,
                args.amendment_sr_ids,
            )
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| RpcError::Contract(format!("SU submit: {e}")))?;
        Ok(*pending.tx_hash())
    }

    // -----------------------------------------------------------------
    // Wait helpers.
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
        let sr = ISpendingRecord::new(SPENDING_RECORD, &provider);
        let ar = IAmendmentRecord::new(AMENDMENT_RECORD, &provider);
        let deadline = Instant::now() + timeout;
        let mut last_missing: Option<U256> = None;
        loop {
            let mut all = true;
            for id in sr_ids {
                if !sr.exists(*id).call().await? {
                    all = false;
                    last_missing = Some(*id);
                    break;
                }
            }
            if all {
                for id in ar_ids {
                    if !ar.exists(*id).call().await? {
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
        let su = ISpendingUnit::new(SPENDING_UNIT, &provider);
        let deadline = Instant::now() + timeout;
        loop {
            let mut all = true;
            for id in su_ids {
                if !su.exists(*id).call().await? {
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

// Re-export the typed-error helpers so scenarios can keep importing
// `crate::clients::sra::into_pso_error` (the prior path).
pub use crate::clients::contract_errors::into_pso_error;
