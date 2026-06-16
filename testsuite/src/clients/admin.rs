//! Admin client — Hardhat #0 in the devnet genesis.
//!
//! Wraps a signing [`L2Client`] bound to the registry admin's
//! secret key. Exposes the registry-mutating surface
//! (`AttestersRegistry.register / revoke / updateMask /
//! setRotationCandidate / initiateAdminTransfer`) plus a read-only
//! view of the current epoch + difficulty.
//!
//! ## Why this exists
//!
//! Before the [`TestEnv`](crate::env::TestEnv) redesign, scenarios
//! reached into `env.admin_key` (raw bytes) and re-implemented the
//! registry ABI inline. That spread the SRA-registration recipe
//! across half a dozen files and made scenarios depend on the
//! Hardhat fixture in subtle ways. Now every admin-side action
//! goes through this type, returning typed errors the suite can
//! match on.
//!
//! ## Surface (today)
//!
//! Working: [`AdminClient::register_sra`],
//! [`AdminClient::revoke_sra`], [`AdminClient::update_mask`],
//! [`AdminClient::set_rotation_candidate`],
//! [`AdminClient::is_active`], [`AdminClient::get_record`],
//! [`AdminClient::current_difficulty`].
//!
//! Stubbed (returning `Err` until the chain ships the dev RPC):
//! [`AdminClient::set_difficulty`]. Tracked in the suite-level
//! TODO. `advance_epoch` shipped as a `TestEnv` method (uses the
//! actor-RPC port).

use alloy::primitives::{Address, TxHash};
use alloy::sol;
use serde_json::json;

use pso_l2_client::{L2Client, L2ClientError};

/// Stable address of the SRA registry precompile-style predeploy.
/// Mirrors `pso-chain/src/predeploys` and the integration tests.
pub const SRA_REGISTRY: Address =
    alloy::primitives::address!("5200000000000000000000000000000000000001");

sol! {
    #[sol(rpc)]
    interface IAttestersRegistry {
        function register(
            address attester,
            uint32 permissionMask,
            bool isRotationCandidate,
            bytes32 consensusKey,
            uint256 p2pAddr
        ) external;
        function revoke(address attester) external;
        function updateMask(address attester, uint32 newMask) external;
        function setRotationCandidate(address attester, bool isRotationCandidate) external;
        function setConsensusIdentity(address attester, bytes32 consensusKey, uint256 p2pAddr) external;
        function isActive(address attester) external view returns (bool);

        /// Mirror of `IAttestersRegistry.AttesterRecord` byte-for-byte. Field
        /// order MUST match the Solidity struct exactly — alloy decodes by
        /// position, not by name, so a misalignment silently reads garbage
        /// into adjacent slots. M3 schema: no `rateLimit`; adds `consensusKey`
        /// + `p2pAddr`.
        /// See `pso-chain-research/contracts/src/interfaces/IAttestersRegistry.sol`.
        struct AttesterRecord {
            bool active;
            uint32 permissionMask;
            uint64 registeredAt;
            bool isRotationCandidate;
            bytes32 consensusKey;
            uint256 p2pAddr;
        }
        function getRecord(address attester) external view returns (AttesterRecord memory);
    }
}

/// Admin client (Hardhat #0 by genesis convention). Cheap to
/// clone — wraps an `Arc<L2Client>`.
#[derive(Clone)]
pub struct AdminClient {
    inner: L2Client,
    rpc_url: String,
}

impl AdminClient {
    /// Build the client from an RPC URL, chain id, and the admin's
    /// 32-byte secp256k1 secret key.
    pub fn new(rpc_url: &str, chain_id: u64, secret_key: &[u8; 32]) -> eyre::Result<Self> {
        let inner = L2Client::connect_with_signer(rpc_url, chain_id, secret_key)
            .map_err(|e| eyre::eyre!("AdminClient connect: {e}"))?;
        Ok(Self {
            inner,
            rpc_url: rpc_url.to_string(),
        })
    }

    /// EVM address of the admin signer.
    pub fn address(&self) -> Address {
        self.inner.signer_address().expect("signer attached")
    }

    /// RPC URL passed at construction.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Underlying `L2Client` — escape hatch for callers that need a
    /// `Provider`.
    pub fn inner(&self) -> &L2Client {
        &self.inner
    }

    // -----------------------------------------------------------------
    // Registry mutations.
    // -----------------------------------------------------------------

    /// `AttestersRegistry.register(attester, permissionMask, isRotationCandidate, consensusKey, p2pAddr)`.
    ///
    /// The M3 `AttestersRegistry` dropped `rateLimit` and added the consensus
    /// identity. A rotation candidate must carry a non-zero `consensusKey`
    /// (contract invariant); the testsuite SRA only needs to be *active* to
    /// submit records, so it registers as a non-rotation attester with a zero
    /// identity. Pass an explicit `consensus_key` (and set
    /// `is_rotation_candidate`) only when a scenario exercises rotation.
    pub async fn register_sra(
        &self,
        sra: Address,
        permission_mask: u32,
        is_rotation_candidate: bool,
        consensus_key: alloy::primitives::B256,
        p2p_addr: alloy::primitives::U256,
    ) -> Result<TxHash, L2ClientError> {
        let provider = self.inner.write_provider()?;
        let reg = IAttestersRegistry::new(SRA_REGISTRY, provider);
        let pending = reg
            .register(
                sra,
                permission_mask,
                is_rotation_candidate,
                consensus_key,
                p2p_addr,
            )
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| L2ClientError::Contract(format!("register: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `AttestersRegistry.revoke(sra)`. After this the SRA's submissions
    /// are bounced with `AttesterNotActive`.
    pub async fn revoke_sra(&self, sra: Address) -> Result<TxHash, L2ClientError> {
        let provider = self.inner.write_provider()?;
        let reg = IAttestersRegistry::new(SRA_REGISTRY, provider);
        let pending = reg
            .revoke(sra)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| L2ClientError::Contract(format!("revoke: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `AttestersRegistry.updateMask(sra, newMask)`.
    pub async fn update_mask(&self, sra: Address, new_mask: u32) -> Result<TxHash, L2ClientError> {
        let provider = self.inner.write_provider()?;
        let reg = IAttestersRegistry::new(SRA_REGISTRY, provider);
        let pending = reg
            .updateMask(sra, new_mask)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| L2ClientError::Contract(format!("updateMask: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `AttestersRegistry.setRotationCandidate(sra, isRotationCandidate)`.
    pub async fn set_rotation_candidate(
        &self,
        sra: Address,
        is_rotation_candidate: bool,
    ) -> Result<TxHash, L2ClientError> {
        let provider = self.inner.write_provider()?;
        let reg = IAttestersRegistry::new(SRA_REGISTRY, provider);
        let pending = reg
            .setRotationCandidate(sra, is_rotation_candidate)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| L2ClientError::Contract(format!("setRotationCandidate: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `AttestersRegistry.setConsensusIdentity(attester, consensusKey, p2pAddr)`.
    /// M3: a non-zero `consensusKey` is the precondition for rotation
    /// candidacy — the contract rejects `setRotationCandidate(true)` without
    /// one. (`p2pAddr` may be 0; the node falls back to `<addr>.pso.network`.)
    pub async fn set_consensus_identity(
        &self,
        sra: Address,
        consensus_key: alloy::primitives::B256,
        p2p_addr: alloy::primitives::U256,
    ) -> Result<TxHash, L2ClientError> {
        let provider = self.inner.write_provider()?;
        let reg = IAttestersRegistry::new(SRA_REGISTRY, provider);
        let pending = reg
            .setConsensusIdentity(sra, consensus_key, p2p_addr)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| L2ClientError::Contract(format!("setConsensusIdentity: {e}")))?;
        Ok(*pending.tx_hash())
    }

    // -----------------------------------------------------------------
    // Registry read views.
    // -----------------------------------------------------------------

    /// `AttestersRegistry.isActive(sra)` — true once admin has registered
    /// and not revoked.
    pub async fn is_active(&self, sra: Address) -> eyre::Result<bool> {
        let provider = self.inner.read_provider();
        let reg = IAttestersRegistry::new(SRA_REGISTRY, &provider);
        Ok(reg.isActive(sra).call().await?)
    }

    /// `AttestersRegistry.getRecord(sra)` — full record (mask, rate
    /// limit, rotation flag, active bit).
    pub async fn get_record(
        &self,
        sra: Address,
    ) -> eyre::Result<IAttestersRegistry::AttesterRecord> {
        let provider = self.inner.read_provider();
        let reg = IAttestersRegistry::new(SRA_REGISTRY, &provider);
        Ok(reg.getRecord(sra).call().await?)
    }

    // -----------------------------------------------------------------
    // Network parameter reads.
    // -----------------------------------------------------------------

    /// `pso_vdfInfo` — the chain's current MinRoot VDF iteration count `T`
    /// (the `current_difficulty` field). Served on both gated ports.
    pub async fn current_difficulty(&self) -> Result<u64, L2ClientError> {
        let resp = self.raw_json_rpc("pso_vdfInfo", json!([])).await?;
        resp.get("current_difficulty")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                L2ClientError::Rpc(format!(
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
    ) -> Result<serde_json::Value, L2ClientError> {
        use alloy::transports::http::reqwest::{Client as HttpClient, Url};
        let url: Url = self
            .rpc_url
            .parse()
            .map_err(|e| L2ClientError::InvalidConfig(format!("rpc url: {e}")))?;
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
            .map_err(|e| L2ClientError::Rpc(format!("post {method}: {e}")))?;
        let text = resp
            .text()
            .await
            .map_err(|e| L2ClientError::Rpc(format!("read {method}: {e}")))?;
        let parsed: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| L2ClientError::Rpc(format!("parse {method} '{text}': {e}")))?;
        if let Some(err) = parsed.get("error") {
            return Err(L2ClientError::Rpc(format!("{method} error: {err}")));
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| L2ClientError::Rpc(format!("{method} missing 'result' in {parsed}")))
    }
}
