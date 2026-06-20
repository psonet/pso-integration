//! Thin alloy RPC handle for the Attester CLI.
//!
//! A small signing provider over the L2 JSON-RPC — the CLI's own copy of
//! the standard alloy provider+signer wiring (there is no shared
//! `l2-client` library crate). SR/AR/SU submits build the
//! `pso-chain-abi` interface instances against it.

use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::{Address, TxHash, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_transport_http::reqwest::Url;
use eyre::Result;

use pso_chain_abi::addresses::{AMENDMENT_RECORD, SPENDING_RECORD, SPENDING_UNIT};
use pso_chain_abi::interfaces::{IAmendmentRecord, ISpendingRecord, ISpendingUnit};

/// Signing JSON-RPC handle for the Attester CLI.
pub struct AttesterRpc {
    url: Url,
    signer: PrivateKeySigner,
}

impl AttesterRpc {
    /// Build from RPC URL, chain id, and a 32-byte secp256k1 secret key.
    pub fn connect(rpc_url: &str, chain_id: u64, secret_key: &[u8; 32]) -> Result<Self> {
        let url = rpc_url.parse::<Url>()?;
        let signer = PrivateKeySigner::from_slice(secret_key)?.with_chain_id(Some(chain_id));
        Ok(Self { url, signer })
    }

    /// The signer's EVM address — the attester's on-chain identity.
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    fn write_provider(&self) -> impl Provider<Ethereum> + Clone {
        let wallet = EthereumWallet::from(self.signer.clone());
        ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.url.clone())
    }

    /// `SpendingRecord.submit(srId)`.
    pub async fn register_spending_record(&self, sr_id: U256) -> Result<TxHash> {
        let inst = ISpendingRecord::new(SPENDING_RECORD, self.write_provider());
        let pending = inst
            .submit(sr_id)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await?;
        Ok(*pending.tx_hash())
    }

    /// `AmendmentRecord.submit(arId)`.
    pub async fn register_amendment_record(&self, ar_id: U256) -> Result<TxHash> {
        let inst = IAmendmentRecord::new(AMENDMENT_RECORD, self.write_provider());
        let pending = inst
            .submit(ar_id)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await?;
        Ok(*pending.tx_hash())
    }

    /// `SpendingUnit.submit(...)`.
    #[allow(clippy::too_many_arguments)]
    pub async fn mint_spending_unit(
        &self,
        su_id: U256,
        derived_owner: alloy_primitives::FixedBytes<32>,
        referrer: Address,
        currency: u16,
        worldwide_day: u32,
        amount_base: u64,
        amount_atto: u64,
        sr_ids: Vec<U256>,
        ar_ids: Vec<U256>,
    ) -> Result<TxHash> {
        let inst = ISpendingUnit::new(SPENDING_UNIT, self.write_provider());
        let pending = inst
            .submit(
                su_id,
                derived_owner,
                referrer,
                currency,
                worldwide_day,
                amount_base,
                amount_atto,
                sr_ids,
                ar_ids,
            )
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await?;
        Ok(*pending.tx_hash())
    }
}
