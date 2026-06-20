//! Admin client — Hardhat #0 in the devnet genesis.
//!
//! Wraps a signing [`RpcHandle`] bound to the registry admin's secret
//! key. Exposes the registry-mutating surface (`AttestersRegistry`
//! register / revoke / updateMask / setRotationCandidate /
//! setConsensusIdentity) plus a read-only view of the current epoch +
//! difficulty.
//!
//! The bulk of the ABI comes from `pso_chain_abi::interfaces::IAttestersRegistry`;
//! `setConsensusIdentity` is not on that interface's vendored ABI, so it
//! is declared inline below.
//!
//! ## Surface (today)
//!
//! Working: [`AdminClient::register_attester`], [`AdminClient::revoke_attester`],
//! [`AdminClient::update_mask`], [`AdminClient::set_rotation_candidate`],
//! [`AdminClient::set_consensus_identity`], [`AdminClient::is_active`],
//! [`AdminClient::get_record`], [`AdminClient::current_difficulty`].
//!
//! Stubbed (returning `Err` until the chain ships the dev RPC):
//! [`AdminClient::set_difficulty`]. `advance_epoch` shipped as a
//! `TestEnv` method (uses the actor-RPC port).

use alloy_primitives::{Address, B256, U256};
use alloy_primitives::TxHash;
use alloy_sol_types::sol;
use serde_json::json;

use pso_chain_abi::addresses::ATTESTERS_REGISTRY;
use pso_chain_abi::interfaces::IAttestersRegistry;

use crate::clients::rpc::{RpcError, RpcHandle};

/// Stable address of the AttestersRegistry predeploy. Re-exported from
/// `pso_chain_abi::addresses::ATTESTERS_REGISTRY` under the historical
/// name so `crate::clients::admin::ATTESTER_REGISTRY` keeps working.
pub const ATTESTER_REGISTRY: Address = ATTESTERS_REGISTRY;

sol! {
    /// `setConsensusIdentity` is part of `AttestersRegistry.sol` but is
    /// not on the vendored `IAttestersRegistry` ABI `pso-chain-abi`
    /// carries; declare just that one method inline.
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IConsensusIdentity {
        function setConsensusIdentity(address attester, bytes32 consensusKey, uint256 p2pAddr) external;
    }
}

/// Admin client (Hardhat #0 by genesis convention). Cheap to
/// clone — wraps an `Arc`-backed [`RpcHandle`].
#[derive(Clone)]
pub struct AdminClient {
    inner: RpcHandle,
    rpc_url: String,
}

impl AdminClient {
    /// Build the client from an RPC URL, chain id, and the admin's
    /// 32-byte secp256k1 secret key.
    pub fn new(rpc_url: &str, chain_id: u64, secret_key: &[u8; 32]) -> eyre::Result<Self> {
        let inner = RpcHandle::connect_with_signer(rpc_url, chain_id, secret_key)
            .map_err(|e| eyre::eyre!("AdminClient connect: {e}"))?;
        Ok(Self {
            inner,
            rpc_url: rpc_url.to_string(),
        })
    }

    /// EVM address of the admin signer.
    #[allow(dead_code)]
    pub fn address(&self) -> Address {
        self.inner.signer_address().expect("signer attached")
    }

    /// RPC URL passed at construction.
    #[allow(dead_code)]
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Underlying [`RpcHandle`] — escape hatch for callers that need a
    /// `Provider`.
    pub fn inner(&self) -> &RpcHandle {
        &self.inner
    }

    // -----------------------------------------------------------------
    // Registry mutations.
    // -----------------------------------------------------------------

    /// `AttestersRegistry.register(attester, permissionMask, isRotationCandidate, consensusKey, p2pAddr)`.
    ///
    /// A rotation candidate must carry a non-zero `consensusKey`
    /// (contract invariant); the testsuite Attester only needs to be *active*
    /// to submit records, so it registers as a non-rotation attester
    /// with a zero identity. Pass an explicit `consensus_key` (and set
    /// `is_rotation_candidate`) only when a scenario exercises rotation.
    pub async fn register_attester(
        &self,
        attester: Address,
        permission_mask: u32,
        is_rotation_candidate: bool,
        consensus_key: B256,
        p2p_addr: U256,
    ) -> Result<TxHash, RpcError> {
        let provider = self.inner.write_provider()?;
        let reg = IAttestersRegistry::new(ATTESTER_REGISTRY, provider);
        let pending = reg
            .register(
                attester,
                permission_mask,
                is_rotation_candidate,
                consensus_key,
                p2p_addr,
            )
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| RpcError::Contract(format!("register: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `AttestersRegistry.revoke(attester)`. After this the Attester's submissions
    /// are bounced with `AttesterNotActive`.
    pub async fn revoke_attester(&self, attester: Address) -> Result<TxHash, RpcError> {
        let provider = self.inner.write_provider()?;
        let reg = IAttestersRegistry::new(ATTESTER_REGISTRY, provider);
        let pending = reg
            .revoke(attester)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| RpcError::Contract(format!("revoke: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `AttestersRegistry.updateMask(attester, newMask)`.
    pub async fn update_mask(&self, attester: Address, new_mask: u32) -> Result<TxHash, RpcError> {
        let provider = self.inner.write_provider()?;
        let reg = IAttestersRegistry::new(ATTESTER_REGISTRY, provider);
        let pending = reg
            .updateMask(attester, new_mask)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| RpcError::Contract(format!("updateMask: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `AttestersRegistry.setRotationCandidate(attester, isRotationCandidate)`.
    pub async fn set_rotation_candidate(
        &self,
        attester: Address,
        is_rotation_candidate: bool,
    ) -> Result<TxHash, RpcError> {
        let provider = self.inner.write_provider()?;
        let reg = IAttestersRegistry::new(ATTESTER_REGISTRY, provider);
        let pending = reg
            .setRotationCandidate(attester, is_rotation_candidate)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| RpcError::Contract(format!("setRotationCandidate: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `AttestersRegistry.setConsensusIdentity(attester, consensusKey, p2pAddr)`.
    /// A non-zero `consensusKey` is the precondition for rotation candidacy —
    /// the contract rejects `setRotationCandidate(true)` without one. (`p2pAddr`
    /// may be 0; the node falls back to `<addr>.pso.network`.)
    pub async fn set_consensus_identity(
        &self,
        attester: Address,
        consensus_key: B256,
        p2p_addr: U256,
    ) -> Result<TxHash, RpcError> {
        let provider = self.inner.write_provider()?;
        let reg = IConsensusIdentity::new(ATTESTER_REGISTRY, provider);
        let pending = reg
            .setConsensusIdentity(attester, consensus_key, p2p_addr)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| RpcError::Contract(format!("setConsensusIdentity: {e}")))?;
        Ok(*pending.tx_hash())
    }

    // -----------------------------------------------------------------
    // Registry read views.
    // -----------------------------------------------------------------

    /// `AttestersRegistry.isActive(attester)` — true once admin has registered
    /// and not revoked.
    pub async fn is_active(&self, attester: Address) -> eyre::Result<bool> {
        let provider = self.inner.read_provider();
        let reg = IAttestersRegistry::new(ATTESTER_REGISTRY, &provider);
        Ok(reg.isActive(attester).call().await?)
    }

    /// `AttestersRegistry.getRecord(attester)` — full record (mask, rotation
    /// flag, active bit, consensus identity).
    pub async fn get_record(
        &self,
        attester: Address,
    ) -> eyre::Result<IAttestersRegistry::AttesterRecord> {
        let provider = self.inner.read_provider();
        let reg = IAttestersRegistry::new(ATTESTER_REGISTRY, &provider);
        Ok(reg.getRecord(attester).call().await?)
    }

    // -----------------------------------------------------------------
    // Network parameter reads.
    // -----------------------------------------------------------------

    /// `pso_vdfInfo` — the chain's current MinRoot VDF iteration count `T`
    /// (the `current_difficulty` field). Served on both gated ports.
    #[allow(dead_code)]
    pub async fn current_difficulty(&self) -> Result<u64, RpcError> {
        let resp = self.raw_json_rpc("pso_vdfInfo", json!([])).await?;
        resp.get("current_difficulty")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                RpcError::Rpc(format!(
                    "pso_vdfInfo missing 'current_difficulty' field: {resp}"
                ))
            })
    }

    // -----------------------------------------------------------------
    // Network parameter writes — stubs.
    //
    // `advance_epoch` shipped on the chain side as
    // `pso_dev_advanceEpoch` (S032 unblock); the real implementation
    // lives on [`crate::env::TestEnv::advance_epoch`] because the
    // method targets the actor RPC port. `set_difficulty` is still a
    // stub pending its chain-side counterpart.
    // -----------------------------------------------------------------

    /// Stub — pinning the chain's MinRoot difficulty for a
    /// scenario that wants deterministic VDF cost across runs.
    /// Tracked as a follow-up.
    #[allow(dead_code)]
    pub async fn set_difficulty(&self, _difficulty: u64) -> eyre::Result<()> {
        Err(eyre::eyre!(
            "AdminClient::set_difficulty: needs `pso_dev_setDifficulty` RPC on the chain; \
             see suite TODO. No-op stub."
        ))
    }

    // -----------------------------------------------------------------
    // Internal plumbing.
    // -----------------------------------------------------------------

    /// Hand-rolled JSON-RPC POST against the RPC URL. Used for
    /// `pso_*` namespaces that aren't on the standard alloy
    /// surface.
    async fn raw_json_rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        use alloy_transport_http::reqwest::{Client as HttpClient, Url};
        let url: Url = self
            .rpc_url
            .parse()
            .map_err(|e| RpcError::InvalidConfig(format!("rpc url: {e}")))?;
        let body = json!({
            "jsonrpc": "2.0",
            "id":      1,
            "method":  method,
            "params":  params,
        });
        let client = HttpClient::new();
        let resp = client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| RpcError::Rpc(format!("post {method}: {e}")))?;
        let text = resp
            .text()
            .await
            .map_err(|e| RpcError::Rpc(format!("read {method}: {e}")))?;
        let parsed: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| RpcError::Rpc(format!("parse {method} '{text}': {e}")))?;
        if let Some(err) = parsed.get("error") {
            return Err(RpcError::Rpc(format!("{method} error: {err}")));
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError::Rpc(format!("{method} missing 'result' in {parsed}")))
    }
}
