//! Admin client — Hardhat #0 in the devnet genesis.
//!
//! Wraps a signing [`L2Client`] bound to the registry admin's
//! secret key. Exposes the registry-mutating surface
//! (`SRARegistry.register / revoke / updateMask /
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
//! [`AdminClient::set_difficulty`], [`AdminClient::advance_epoch`].
//! Both are tracked in the suite-level TODO. Scenarios needing
//! them can still reference the method today and they will Just
//! Work once the chain side lands.

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
    interface ISRARegistry {
        function register(
            address sra,
            uint32 permissionMask,
            uint64 rateLimit,
            bool isRotationCandidate
        ) external;
        function revoke(address sra) external;
        function updateMask(address sra, uint32 newMask) external;
        function setRotationCandidate(address sra, bool isRotationCandidate) external;
        function isActive(address sra) external view returns (bool);

        /// Mirror of `ISRARegistry.SRARecord` byte-for-byte. Field
        /// order MUST match the Solidity struct exactly — alloy
        /// decodes by position, not by name, so a misalignment
        /// silently reads garbage into adjacent slots.
        /// See `pso-chain/contracts/src/interfaces/ISRARegistry.sol:14`.
        struct SRARecord {
            bool active;
            uint32 permissionMask;
            uint64 rateLimit;
            uint64 registeredAt;
            bool isRotationCandidate;
        }
        function getRecord(address sra) external view returns (SRARecord memory);
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

    /// `SRARegistry.register(sra, permissionMask, rateLimit, isRotationCandidate)`.
    pub async fn register_sra(
        &self,
        sra: Address,
        permission_mask: u32,
        rate_limit: u64,
        is_rotation_candidate: bool,
    ) -> Result<TxHash, L2ClientError> {
        let provider = self.inner.write_provider()?;
        let reg = ISRARegistry::new(SRA_REGISTRY, provider);
        let pending = reg
            .register(sra, permission_mask, rate_limit, is_rotation_candidate)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| L2ClientError::Contract(format!("register: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `SRARegistry.revoke(sra)`. After this the SRA's submissions
    /// are bounced with `SRANotActive`.
    pub async fn revoke_sra(&self, sra: Address) -> Result<TxHash, L2ClientError> {
        let provider = self.inner.write_provider()?;
        let reg = ISRARegistry::new(SRA_REGISTRY, provider);
        let pending = reg
            .revoke(sra)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| L2ClientError::Contract(format!("revoke: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `SRARegistry.updateMask(sra, newMask)`.
    pub async fn update_mask(&self, sra: Address, new_mask: u32) -> Result<TxHash, L2ClientError> {
        let provider = self.inner.write_provider()?;
        let reg = ISRARegistry::new(SRA_REGISTRY, provider);
        let pending = reg
            .updateMask(sra, new_mask)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| L2ClientError::Contract(format!("updateMask: {e}")))?;
        Ok(*pending.tx_hash())
    }

    /// `SRARegistry.setRotationCandidate(sra, isRotationCandidate)`.
    pub async fn set_rotation_candidate(
        &self,
        sra: Address,
        is_rotation_candidate: bool,
    ) -> Result<TxHash, L2ClientError> {
        let provider = self.inner.write_provider()?;
        let reg = ISRARegistry::new(SRA_REGISTRY, provider);
        let pending = reg
            .setRotationCandidate(sra, is_rotation_candidate)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await
            .map_err(|e| L2ClientError::Contract(format!("setRotationCandidate: {e}")))?;
        Ok(*pending.tx_hash())
    }

    // -----------------------------------------------------------------
    // Registry read views.
    // -----------------------------------------------------------------

    /// `SRARegistry.isActive(sra)` — true once admin has registered
    /// and not revoked.
    pub async fn is_active(&self, sra: Address) -> eyre::Result<bool> {
        let provider = self.inner.read_provider();
        let reg = ISRARegistry::new(SRA_REGISTRY, &provider);
        Ok(reg.isActive(sra).call().await?)
    }

    /// `SRARegistry.getRecord(sra)` — full record (mask, rate
    /// limit, rotation flag, active bit).
    pub async fn get_record(&self, sra: Address) -> eyre::Result<ISRARegistry::SRARecord> {
        let provider = self.inner.read_provider();
        let reg = ISRARegistry::new(SRA_REGISTRY, &provider);
        Ok(reg.getRecord(sra).call().await?)
    }

    // -----------------------------------------------------------------
    // Network parameter reads.
    // -----------------------------------------------------------------

    /// `pso_epochDifficulty` — the chain's current MinRoot VDF
    /// iteration count `T`. Hits the actor RPC directly (the
    /// agents pool exposes the same endpoint).
    pub async fn current_difficulty(&self) -> Result<u64, L2ClientError> {
        let resp = self.raw_json_rpc("pso_epochDifficulty", json!([])).await?;
        resp.get("difficulty")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                L2ClientError::Rpc(format!(
                    "pso_epochDifficulty missing 'difficulty' field: {resp}"
                ))
            })
    }

    // -----------------------------------------------------------------
    // Network parameter writes — stubs.
    //
    // These need chain-side dev RPCs that don't ship today
    // (`pso_dev_setDifficulty`, `pso_dev_advanceEpoch`). The
    // signatures are stable; once the chain side lands, the
    // implementations become real RPC calls without breaking
    // scenarios that already reference these methods.
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

    /// Stub — forcing an epoch transition (needed for the S032
    /// previous-T-fallback positive scenario). Tracked as task #34.
    pub async fn advance_epoch(&self) -> eyre::Result<()> {
        Err(eyre::eyre!(
            "AdminClient::advance_epoch: needs `pso_dev_advanceEpoch` RPC on the chain; \
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
