//! `RpcHandle` — alloy JSON-RPC + signer handle for PSO L2.
//!
//! The testsuite's Attester + admin clients take an `RpcHandle` and perform
//! their operations through it. The signer can be omitted for read-only
//! interactions (e.g. inspecting on-chain state); any write-path
//! function returns [`RpcError::NoSigner`] when the caller forgot to
//! attach one.
//!
//! This is a small local re-implementation of the (removed)
//! `pso-l2-client::client::L2Client` — the testsuite owns its client
//! layer now.

use std::sync::Arc;

use alloy_network::EthereumWallet;
use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_transport_http::reqwest::Url;
use thiserror::Error;

/// Top-level error returned by the testsuite's RPC client surface.
#[derive(Debug, Error)]
pub enum RpcError {
    /// Failed to parse an RPC URL or other configuration string.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The caller asked for a signed operation but the client was
    /// constructed without a signer.
    #[error("operation requires a signing wallet; client was built read-only")]
    NoSigner,

    /// JSON-RPC, network, or alloy-internal error. Boxed as a String
    /// because alloy's `RpcError` is parameterised and unwieldy to
    /// surface directly through the public API.
    #[error("rpc error: {0}")]
    Rpc(String),

    /// Contract call reverted or returned malformed data. The typed
    /// [`PsoContractError`](crate::clients::contract_errors::PsoContractError)
    /// decoder keys off this variant's text.
    #[error("contract call failed: {0}")]
    Contract(String),
}

/// JSON-RPC handle for PSO L2, optionally augmented with a signer.
///
/// Cheap to clone — internal state lives behind an `Arc`. Build with
/// [`RpcHandle::connect`] for read-only mode, or
/// [`RpcHandle::connect_with_signer`] to sign transactions.
#[derive(Clone)]
pub struct RpcHandle {
    inner: Arc<Inner>,
}

struct Inner {
    rpc_url: Url,
    chain_id: u64,
    signer: Option<PrivateKeySigner>,
}

impl RpcHandle {
    /// Connect to an L2 RPC endpoint in **read-only** mode.
    ///
    /// `rpc_url` must be a `http://` or `https://` URL of an L2 node's
    /// JSON-RPC interface. `chain_id` is the L2 chain id (devnet
    /// `19_280_501`).
    #[allow(dead_code)]
    pub fn connect(rpc_url: &str, chain_id: u64) -> Result<Self, RpcError> {
        let url = rpc_url
            .parse::<Url>()
            .map_err(|e| RpcError::InvalidConfig(format!("rpc url: {e}")))?;
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
    /// `secret_key_bytes` is a 32-byte secp256k1 scalar.
    pub fn connect_with_signer(
        rpc_url: &str,
        chain_id: u64,
        secret_key_bytes: &[u8; 32],
    ) -> Result<Self, RpcError> {
        let url = rpc_url
            .parse::<Url>()
            .map_err(|e| RpcError::InvalidConfig(format!("rpc url: {e}")))?;
        let signer = PrivateKeySigner::from_slice(secret_key_bytes)
            .map_err(|e| RpcError::InvalidConfig(format!("secret key: {e}")))?
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
    pub fn write_provider(&self) -> Result<impl Provider + Clone, RpcError> {
        let signer = self.inner.signer.clone().ok_or(RpcError::NoSigner)?;
        let wallet = EthereumWallet::from(signer);
        Ok(ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.inner.rpc_url.clone()))
    }
}
