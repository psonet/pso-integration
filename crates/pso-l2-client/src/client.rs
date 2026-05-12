//! `L2Client` — alloy JSON-RPC + signer handle for PSO L2.
//!
//! Both SRA and Wallet flows take an `&L2Client` and perform their
//! operations through it. The signer can be omitted for read-only
//! interactions (e.g. inspecting on-chain state in tests); any
//! write-path function returns [`crate::L2ClientError::NoSigner`] when
//! the caller forgot to attach one.

use std::sync::Arc;

use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::transports::http::reqwest::Url;

use crate::error::L2ClientError;

/// JSON-RPC handle for PSO L2, optionally augmented with a signer.
///
/// Cheap to clone — internal state lives behind an `Arc`. Build with
/// [`L2Client::connect`] for read-only mode, or
/// [`L2Client::connect_with_signer`] to sign transactions.
#[derive(Clone)]
pub struct L2Client {
    inner: Arc<Inner>,
}

struct Inner {
    rpc_url: Url,
    chain_id: u64,
    signer: Option<PrivateKeySigner>,
}

impl L2Client {
    /// Connect to an L2 RPC endpoint in **read-only** mode.
    ///
    /// `rpc_url` must be a `http://` or `https://` URL of an L2 node's
    /// JSON-RPC interface. `chain_id` is the L2 chain id (devnet
    /// `19_280_501`).
    pub fn connect(rpc_url: &str, chain_id: u64) -> Result<Self, L2ClientError> {
        let url = rpc_url
            .parse::<Url>()
            .map_err(|e| L2ClientError::InvalidConfig(format!("rpc url: {e}")))?;
        Ok(Self {
            inner: Arc::new(Inner {
                rpc_url: url,
                chain_id,
                signer: None,
            }),
        })
    }

    /// Connect with a signing wallet attached.
    ///
    /// `secret_key_bytes` is a 32-byte secp256k1 scalar (the same shape
    /// `pso_integrations_shared::parse_secret_key` accepts).
    pub fn connect_with_signer(
        rpc_url: &str,
        chain_id: u64,
        secret_key_bytes: &[u8; 32],
    ) -> Result<Self, L2ClientError> {
        let url = rpc_url
            .parse::<Url>()
            .map_err(|e| L2ClientError::InvalidConfig(format!("rpc url: {e}")))?;
        let signer = PrivateKeySigner::from_slice(secret_key_bytes)
            .map_err(|e| L2ClientError::InvalidConfig(format!("secret key: {e}")))?
            .with_chain_id(Some(chain_id));
        Ok(Self {
            inner: Arc::new(Inner {
                rpc_url: url,
                chain_id,
                signer: Some(signer),
            }),
        })
    }

    /// Configured chain id.
    pub fn chain_id(&self) -> u64 {
        self.inner.chain_id
    }

    /// EVM address of the attached signer, if any.
    pub fn signer_address(&self) -> Option<Address> {
        self.inner.signer.as_ref().map(|s| s.address())
    }

    /// Build a fresh provider for a read-only RPC call.
    pub fn read_provider(&self) -> impl Provider + Clone {
        ProviderBuilder::new().connect_http(self.inner.rpc_url.clone())
    }

    /// Build a provider that signs and broadcasts transactions using
    /// the attached signer.
    pub fn write_provider(&self) -> Result<impl Provider + Clone, L2ClientError> {
        let signer = self.inner.signer.clone().ok_or(L2ClientError::NoSigner)?;
        let wallet = EthereumWallet::from(signer);
        Ok(ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.inner.rpc_url.clone()))
    }

    /// Fetch the current L2 block number (handy for VDF input
    /// construction and freshness checks).
    pub async fn block_number(&self) -> Result<u64, L2ClientError> {
        self.read_provider()
            .get_block_number()
            .await
            .map_err(|e| L2ClientError::Rpc(e.to_string()))
    }

    /// Fetch the signer's current pending nonce. Returns
    /// `NoSigner` when the client was built read-only.
    pub async fn signer_nonce(&self) -> Result<u64, L2ClientError> {
        let addr = self.signer_address().ok_or(L2ClientError::NoSigner)?;
        self.read_provider()
            .get_transaction_count(addr)
            .pending()
            .await
            .map_err(|e| L2ClientError::Rpc(e.to_string()))
    }
}
