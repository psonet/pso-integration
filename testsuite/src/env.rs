//! Shared test environment.
//!
//! [`TestEnv`] bundles every handle scenarios need:
//!
//! - The two RPC URLs (agents-pool, actor-pool) and the chain id
//!   passed in from the CLI.
//! - An [`SraClient`] bound to the CLI-supplied `--sra-key`. We
//!   register the address with the on-chain `SRARegistry` (via
//!   [`bootstrap_register_sra`]) before scenarios run, so every
//!   `onlyActiveSRA`-gated submit path accepts it.
//! - An [`ActorClient`] bound to the CLI-supplied `--wallet-key` (or a
//!   freshly rolled `OsRng` key if the flag was omitted).
//! - The CLI-supplied `--admin-key`, kept around so per-scenario
//!   helpers like [`TestEnv::register_random_sra`] can promote
//!   additional SRAs at runtime without referring back to the
//!   Hardhat fixture.
//! - A [`Bridge`] handle wrapping the SRA bridge background task.
//!
//! [`TestEnv::bootstrap_from_cli`] is idempotent — re-running the
//! suite against a warm node short-circuits the on-chain SRA
//! registration. Scenarios borrow the env across the (single) tokio
//! runtime the binary's `main` builds; the `OnceCell`-backed shared
//! env from the cargo-test version is gone.

use alloy::primitives::Address;
use k256::SecretKey;
use rand::rngs::OsRng;
use rand::RngCore;

use pso_l2_client::{L2Client, L2ClientError};

use crate::bridge::{spawn_sra_loop, Bridge};
use crate::cli::Cli;
use crate::clients::actor::ActorClient;
use crate::clients::sra::SraClient;

/// All-in-one handle every scenario takes by reference.
pub struct TestEnv {
    /// Agents-pool RPC URL.
    pub rpc_url: String,
    /// Actor-pool RPC URL.
    pub actor_rpc_url: String,
    /// Chain id passed at CLI construction.
    pub chain_id: u64,
    /// Address of the registry admin (derived from `--admin-key`).
    pub admin_addr: Address,
    /// Admin secret key. Stored so [`Self::register_random_sra`] can
    /// promote auxiliary SRAs at runtime.
    pub admin_key: [u8; 32],
    /// Primary SRA secret key. Stored alongside the [`SraClient`] so
    /// scenarios that need to spin up alternate clients bound to the
    /// **same** SRA address (e.g. S006 building an actor-pool client
    /// from the SRA key) can do so without depending on the Hardhat
    /// fixture.
    pub sra_key: [u8; 32],
    /// Primary SRA client.
    pub sra: SraClient,
    /// Wallet client used by every scenario that submits via the
    /// actor pool. Either the `--wallet-key` from the CLI or a fresh
    /// `OsRng`-rolled key.
    pub actor: ActorClient,
    /// SRA bridge handle. The background task lives for the duration
    /// of the binary; scenarios just call `env.bridge.mint_su(...)`.
    pub bridge: Bridge,
}

impl TestEnv {
    /// Build the env from a parsed CLI. Idempotent w.r.t. the
    /// on-chain SRA registration: if the primary SRA is already
    /// active we skip the register tx.
    ///
    /// Steps:
    /// 1. Build an [`SraClient`] from `cli.sra_key`.
    /// 2. Promote that address with the registry admin (the CLI's
    ///    `--admin-key`).
    /// 3. Build an [`ActorClient`] from `cli.wallet_key` (or a fresh
    ///    `OsRng` key).
    /// 4. Spawn the SRA bridge background task.
    pub async fn bootstrap_from_cli(cli: &Cli) -> eyre::Result<Self> {
        let rpc_url = cli.rpc_url.clone();
        let actor_rpc_url = cli.actor_rpc_url.clone();
        let chain_id = cli.chain_id;

        // -----------------------------------------------------------------
        // SRA registry bootstrap. The admin owns `SRARegistry`; we
        // promote the SRA signer to an active SRA with full
        // permissions so every onlyActiveSRA-gated submit path
        // accepts it.
        // -----------------------------------------------------------------
        bootstrap_register_sra(&rpc_url, chain_id, &cli.sra_key, &cli.admin_key).await?;

        let admin_addr = derive_address(&cli.admin_key)?;
        let sra = SraClient::new(&rpc_url, chain_id, &cli.sra_key)?;

        let wallet_key = cli.wallet_key.unwrap_or_else(roll_random_key);
        let actor = ActorClient::new(&actor_rpc_url, chain_id, &wallet_key)
            .map_err(|e| eyre::eyre!("ActorClient: {e}"))?;

        let bridge = spawn_sra_loop(sra.clone());

        Ok(Self {
            rpc_url,
            actor_rpc_url,
            chain_id,
            admin_addr,
            admin_key: cli.admin_key,
            sra_key: cli.sra_key,
            sra,
            actor,
            bridge,
        })
    }

    /// Promote a freshly rolled secret-key address into the SRA
    /// registry and hand back an [`SraClient`] bound to it.
    ///
    /// Used by S009 to model "two distinct SRAs trying to mint each
    /// other's SUs". The Hardhat-indexed `register_extra_sra(idx)`
    /// from the cargo-test version is gone — we use random keys
    /// per call so scenarios don't share an index space across
    /// reruns.
    pub async fn register_random_sra(&self) -> eyre::Result<SraClient> {
        let secret = roll_random_key();
        bootstrap_register_sra(&self.rpc_url, self.chain_id, &secret, &self.admin_key).await?;
        SraClient::new(&self.rpc_url, self.chain_id, &secret)
    }
}

/// Roll a fresh 32-byte secp256k1 secret key from `OsRng`. The
/// statistical chance of producing zero or a value ≥ `n` is
/// negligible — every downstream constructor revalidates anyway.
fn roll_random_key() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// EVM address for a 32-byte secp256k1 secret key. Routes through
/// `k256::SecretKey` so we surface a typed error if the bytes don't
/// land in a valid scalar.
fn derive_address(secret: &[u8; 32]) -> eyre::Result<Address> {
    use alloy::signers::local::PrivateKeySigner;
    let _ = SecretKey::from_slice(secret).map_err(|e| eyre::eyre!("admin key invalid: {e}"))?;
    let signer = PrivateKeySigner::from_slice(secret)
        .map_err(|e| eyre::eyre!("admin key signer build: {e}"))?;
    Ok(signer.address())
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

const SRA_REGISTRY: Address =
    alloy::primitives::address!("5200000000000000000000000000000000000001");

/// Register `target_secret_key`'s address with the SRA registry,
/// signing with `admin_secret_key` (the registry admin's secret key
/// — supplied by the CLI). No-op if the address is already active.
///
/// The cargo-test version of this helper hardcoded "Hardhat #0" as
/// the admin; the CLI variant takes the admin key explicitly so
/// pso-chain CI can wire up whatever admin key the devnet container
/// is configured with.
pub async fn bootstrap_register_sra(
    rpc: &str,
    chain_id: u64,
    target_secret_key: &[u8; 32],
    admin_secret_key: &[u8; 32],
) -> eyre::Result<()> {
    let target_client =
        L2Client::connect_with_signer(rpc, chain_id, target_secret_key).map_err(map_l2_err)?;
    let target_addr = target_client
        .signer_address()
        .ok_or_else(|| eyre::eyre!("SRA signer missing"))?;

    let read_provider = target_client.read_provider();
    let registry = ISRARegistry::new(SRA_REGISTRY, &read_provider);
    if registry.isActive(target_addr).call().await? {
        return Ok(());
    }

    let admin_client =
        L2Client::connect_with_signer(rpc, chain_id, admin_secret_key).map_err(map_l2_err)?;
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
