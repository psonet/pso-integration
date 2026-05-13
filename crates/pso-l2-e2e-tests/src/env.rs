//! Shared test environment.
//!
//! [`TestEnv`] bundles every handle scenarios need:
//!
//! - The two RPC URLs (agents-pool at `:19545`, actor-pool at `:8546`).
//! - An [`SraClient`] bound to Hardhat-mnemonic key #1 — the
//!   primary SRA across the suite.
//! - An [`ActorClient`] bound to Hardhat-mnemonic key #2 — a generic
//!   "wallet" used by S003-S006.
//! - A [`Bridge`] handle wrapping the SRA bridge background task.
//!
//! [`TestEnv::bootstrap`] is idempotent — re-running tests against a
//! warm node short-circuits the on-chain SRA registration. Tests
//! reuse a single global env via [`TestEnv::shared`] (a
//! `tokio::sync::OnceCell`); the `#[serial_test::serial]` attribute
//! on the test functions ensures bodies don't trample each other.

use std::sync::Arc;

use alloy::primitives::Address;
use tokio::sync::OnceCell;

use pso_l2_client::{L2Client, L2ClientError};

use crate::bridge::{spawn_sra_loop, Bridge};
use crate::clients::actor::ActorClient;
use crate::clients::sra::SraClient;
use crate::hardhat::{signer_address, signer_key};
use crate::{actor_rpc_url, rpc_url, DEVNET_CHAIN_ID};

/// All-in-one handle every scenario takes by reference.
pub struct TestEnv {
    /// Agents-pool RPC URL (defaults to `127.0.0.1:19545`).
    pub rpc_url: String,
    /// Actor-pool RPC URL (defaults to `127.0.0.1:8546`).
    pub actor_rpc_url: String,
    /// Devnet chain id (`19_280_501`).
    pub chain_id: u64,
    /// Address of Hardhat #0 (registry admin).
    pub admin_addr: Address,
    /// Primary SRA client (Hardhat #1).
    pub sra: SraClient,
    /// Generic wallet client (Hardhat #2) — used by every scenario
    /// that submits via the actor pool.
    pub actor: ActorClient,
    /// SRA bridge handle. The background task lives for the
    /// duration of the test process; scenarios just call
    /// `env.bridge.mint_su(...)`.
    pub bridge: Bridge,
}

impl TestEnv {
    /// Build a fresh env. Idempotent: if Hardhat #1 is already an
    /// active SRA we skip the registration tx.
    pub async fn bootstrap() -> eyre::Result<Self> {
        let rpc_url = rpc_url();
        let actor_rpc_url = actor_rpc_url();
        let chain_id = DEVNET_CHAIN_ID;

        // -----------------------------------------------------------------
        // SRA registry bootstrap. The admin owns `SRARegistry`;
        // tests promote Hardhat #1 to an active SRA with full
        // permissions so every onlyActiveSRA-gated submit path
        // accepts it.
        // -----------------------------------------------------------------
        bootstrap_register_sra(&rpc_url, chain_id, &signer_key(1)).await?;

        let admin_addr = signer_address(0);
        let sra = SraClient::new(&rpc_url, chain_id, &signer_key(1))?;
        let actor = ActorClient::new(&actor_rpc_url, chain_id, &signer_key(2))
            .map_err(|e| eyre::eyre!("ActorClient: {e}"))?;
        let bridge = spawn_sra_loop(sra.clone());

        Ok(Self {
            rpc_url,
            actor_rpc_url,
            chain_id,
            admin_addr,
            sra,
            actor,
            bridge,
        })
    }

    /// Process-wide shared instance. Tests reuse it across the
    /// `serial_test::serial`-gated bodies; the OnceCell guarantees
    /// the bootstrap runs exactly once even under concurrent
    /// first-touch.
    pub async fn shared() -> eyre::Result<&'static TestEnv> {
        // Static slot — `Arc<TestEnv>` lives in the OnceCell so the
        // borrow we hand back is `&'static`. The Arc never drops
        // (we hold a reference for the test process lifetime).
        static CELL: OnceCell<Arc<TestEnv>> = OnceCell::const_new();
        let arc = CELL
            .get_or_try_init(|| async {
                let env = TestEnv::bootstrap().await?;
                Ok::<_, eyre::Report>(Arc::new(env))
            })
            .await?;
        // Safe: `arc` lives as long as the static OnceCell, which is
        // for the program's lifetime. We leak a stable reference.
        let static_ref: &'static TestEnv = unsafe { &*(Arc::as_ptr(arc) as *const TestEnv) };
        Ok(static_ref)
    }

    /// Promote an extra Hardhat-indexed signer into the SRA registry
    /// and hand back an [`SraClient`] bound to it. Used by S009 to
    /// model "two distinct SRAs trying to mint each other's SUs".
    /// Idempotent — if the signer is already active we skip the
    /// register tx.
    pub async fn register_extra_sra(&self, idx: usize) -> eyre::Result<SraClient> {
        bootstrap_register_sra(&self.rpc_url, self.chain_id, &signer_key(idx)).await?;
        SraClient::new(&self.rpc_url, self.chain_id, &signer_key(idx))
    }
}

// -----------------------------------------------------------------
// SRA registry bootstrap — minimal SOL ABI inline. We can't share
// `pso-l2-client::abi` because the registry interface isn't in that
// crate's surface; mirroring it here matches the layout of the
// original `tests/full_flow.rs::bootstrap_register_sra`.
// -----------------------------------------------------------------

alloy::sol! {
    #[sol(rpc)]
    interface ISRARegistry {
        function isActive(address sra) external view returns (bool);
        function register(
            address sra,
            uint32 permissionMask,
            uint64 rateLimit,
            bool isRotationCandidate
        ) external;
    }
}

const SRA_REGISTRY: Address = alloy::primitives::address!(
    "5200000000000000000000000000000000000001"
);

/// Register `target_secret_key`'s address with the SRA registry,
/// signing with Hardhat #0 (the registry admin baked into the devnet
/// genesis). No-op if the address is already active.
pub async fn bootstrap_register_sra(
    rpc: &str,
    chain_id: u64,
    target_secret_key: &[u8; 32],
) -> eyre::Result<()> {
    let target_client = L2Client::connect_with_signer(rpc, chain_id, target_secret_key)
        .map_err(map_l2_err)?;
    let target_addr = target_client
        .signer_address()
        .ok_or_else(|| eyre::eyre!("SRA signer missing"))?;

    let read_provider = target_client.read_provider();
    let registry = ISRARegistry::new(SRA_REGISTRY, &read_provider);
    if registry.isActive(target_addr).call().await? {
        return Ok(());
    }

    let admin_client = L2Client::connect_with_signer(rpc, chain_id, &signer_key(0))
        .map_err(map_l2_err)?;
    let write_provider = admin_client.write_provider().map_err(map_l2_err)?;
    let registry_w = ISRARegistry::new(SRA_REGISTRY, &write_provider);
    let pending = registry_w
        .register(target_addr, u32::MAX, 1_000_000u64, true)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await?;
    pending.get_receipt().await?;
    Ok(())
}

fn map_l2_err(e: L2ClientError) -> eyre::Report {
    eyre::eyre!("l2 client: {e}")
}

/// Initialise tracing for the test process. Idempotent — safe to
/// call from every scenario body.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("PSO_LOG").unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}
