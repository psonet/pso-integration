//! Thin alloy RPC handle for the wallet CLI.
//!
//! A small signing provider over the L2 JSON-RPC — the CLI's own copy of
//! the standard alloy provider+signer wiring. `submit-td` builds the
//! `pso-chain-abi` `ITributeDraft` instance against it.

use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::{Bytes, FixedBytes, TxHash, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_transport_http::reqwest::Url;
use eyre::Result;

use pso_chain_abi::addresses::TRIBUTE_DRAFT;
use pso_chain_abi::interfaces::ITributeDraft;

/// Signing JSON-RPC handle for the wallet CLI.
pub struct WalletRpc {
    url: Url,
    signer: PrivateKeySigner,
}

impl WalletRpc {
    /// Build from RPC URL, chain id, and a 32-byte secp256k1 secret key.
    pub fn connect(rpc_url: &str, chain_id: u64, secret_key: &[u8; 32]) -> Result<Self> {
        let url = rpc_url.parse::<Url>()?;
        let signer = PrivateKeySigner::from_slice(secret_key)?.with_chain_id(Some(chain_id));
        Ok(Self { url, signer })
    }

    fn write_provider(&self) -> impl Provider<Ethereum> + Clone {
        let wallet = EthereumWallet::from(self.signer.clone());
        ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.url.clone())
    }

    /// `TributeDraft.submit(tdId, derivedOwner, suIds, aggregationProof)`.
    pub async fn submit_tribute_draft(
        &self,
        td_id: U256,
        derived_owner: FixedBytes<32>,
        su_ids: Vec<U256>,
        aggregation_proof: Bytes,
    ) -> Result<TxHash> {
        let inst = ITributeDraft::new(TRIBUTE_DRAFT, self.write_provider());
        let pending = inst
            .submit(td_id, derived_owner, su_ids, aggregation_proof)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await?;
        Ok(*pending.tx_hash())
    }
}
