//! Shared test environment.
//!
//! [`TestEnv`] is the **one** handle every scenario takes by
//! reference. Everything else — admin client, SRA-0 client,
//! actor pool, bridge — lives behind methods on this type so a
//! scenario can be reasoned about top-to-bottom from its single
//! `&env` parameter.
//!
//! ## Conceptual surface
//!
//! - **`env.admin`** — Hardhat #0 in the devnet genesis. Holds the
//!   registry-mutating API (`register_sra` / `revoke_sra` /
//!   `update_mask` / `set_rotation_candidate`), the read views
//!   (`is_active` / `get_record`), and a small set of network
//!   parameter accessors (`current_difficulty`; `set_difficulty`
//!   still stubbed pending a chain-side dev RPC).
//! - **`env.advance_epoch(new_difficulty)`** — test-only knob that
//!   rolls the chain's `DifficultyState` via `pso_dev_advanceEpoch`
//!   on the actor RPC. Used by S032 (cross-epoch positive). Needs
//!   pso-chain spawned with `PSO_DEV_RPC=1`.
//! - **`env.sra_zero`** — Hardhat #1 in the devnet genesis,
//!   pre-registered by [`bootstrap_register_sra`] before any
//!   scenario runs. Use this for the "happy-path SRA" view.
//! - **`env.new_sra()`** — async helper that rolls a fresh
//!   secp256k1 key, registers it via [`AdminClient::register_sra`],
//!   and returns an [`SraClient`] bound to it. Used by S009 and
//!   the SRA-lifecycle scenarios that need a *second* SRA in play.
//! - **`env.new_actor()`** — fresh [`ActorClient`] keyed by a
//!   random non-SRA wallet key. The actor RPC's `add_raw_tx`
//!   rejects any non-SRA sender as "SRA not registered:" — use
//!   this when the *test surface* is precisely that rejection
//!   (S003-S005, S030).
//! - **`env.new_actor_as_sra(&sra)`** — fresh [`ActorClient`]
//!   keyed by the supplied SRA. Use this when the scenario wants
//!   to clear the SRA-registered gate and exercise a *post-gate*
//!   validator (envelope tampering S013-S017, VDF difficulty
//!   mismatch S031, …).
//! - **`env.bridge`** — the long-lived SRA bridge background task
//!   used by SU-mint scenarios.

use alloy_primitives::Address;
use k256::SecretKey;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::bridge::{spawn_sra_loop, Bridge};
use crate::cli::Cli;
use crate::clients::actor::ActorClient;
use crate::clients::admin::{AdminClient, SRA_REGISTRY};
use crate::clients::rpc::{RpcError, RpcHandle};
use crate::clients::sra::SraClient;

/// Permission mask SRAs are registered with: bits 0–3 = SU.submit,
/// SR.submit, AR.submit, heartbeat (reserved) — the same mask the
/// node's own dev seeding uses for the sequencer (`main.rs`,
/// `permission_mask: 15`).
///
/// Deliberately NOT `u32::MAX`: that is `ADMIN_MASK`, which
/// short-circuits the agents-lane `(to, selector)` allowlist
/// entirely and previously let SRAs relay `TributeDraft.submit`
/// through the agents pool — a backdoor, since `TD.submit` is not
/// in the allowlist at all. Real topology: TDs are wallet-submitted
/// through the actor pool only.
pub const SRA_PERMISSION_MASK: u32 = 0xF;

/// All-in-one handle every scenario takes by reference. See the
/// module-level doc-comment for the conceptual surface.
pub struct TestEnv {
    /// Agents-pool RPC URL.
    pub rpc_url: String,
    /// Actor-pool RPC URL.
    pub actor_rpc_url: String,
    /// Chain id passed at CLI construction.
    pub chain_id: u64,

    /// Hardhat #0 — admin signer + registry-mutating API +
    /// difficulty / epoch hooks.
    pub admin: AdminClient,

    /// Hardhat #1 — the bootstrapped primary SRA. Pre-registered
    /// with `permissionMask = u32::MAX` and `isRotationCandidate
    /// = true`.
    pub sra_zero: SraClient,

    /// SRA bridge handle. The background task lives for the
    /// duration of the binary; scenarios just call
    /// `env.bridge.mint_su(...)`.
    pub bridge: Bridge,

    /// Raw SRA-0 secret-key bytes. Exposed for the narrow set of
    /// internal helpers that need to build a *new*
    /// [`ActorClient`] from this key without paying for the
    /// public method's I/O — most scenarios should call
    /// [`Self::new_actor_as_sra`] with `&env.sra_zero` instead.
    pub(crate) sra_zero_key: [u8; 32],

    /// L1 JSON-RPC the chain posts DA batches to (`--l1-rpc-url`).
    /// `None` unless the caller wired the data-availability scenario
    /// (S045); paired with [`Self::da_inbox`].
    pub l1_rpc_url: Option<String>,

    /// Deployed `DaInbox` address on [`Self::l1_rpc_url`] (`--da-inbox`).
    /// `None` unless the DA scenario is wired.
    pub da_inbox: Option<Address>,
}

impl TestEnv {
    /// Build the env from a parsed CLI. Idempotent w.r.t. the
    /// on-chain SRA-0 registration: re-running against a warm node
    /// is a no-op.
    pub async fn bootstrap_from_cli(cli: &Cli) -> eyre::Result<Self> {
        let rpc_url = cli.rpc_url.clone();
        let actor_rpc_url = cli.actor_rpc_url.clone();
        let chain_id = cli.chain_id;

        // The admin owns `SRARegistry`. Bootstrap before building
        // the SRA-0 client so every `onlyActiveSRA`-gated submit
        // path accepts it from tick zero.
        // CLI `required_unless_present = "list"` means both keys
        // ARE here when we reach this code path (bootstrap is only
        // called for a real scenario run, not for `--list`).
        let admin_key = cli
            .admin_key
            .ok_or_else(|| eyre::eyre!("--admin-key required for live runs"))?;
        let sra_key = cli
            .sra_key
            .ok_or_else(|| eyre::eyre!("--sra-key required for live runs"))?;

        bootstrap_register_sra(&rpc_url, chain_id, &sra_key, &admin_key).await?;

        let admin = AdminClient::new(&rpc_url, chain_id, &admin_key)
            .map_err(|e| eyre::eyre!("AdminClient: {e}"))?;
        let sra_zero = SraClient::new(&rpc_url, chain_id, &sra_key)?;
        let bridge = spawn_sra_loop(sra_zero.clone());

        Ok(Self {
            rpc_url,
            actor_rpc_url,
            chain_id,
            admin,
            sra_zero,
            bridge,
            sra_zero_key: sra_key,
            l1_rpc_url: cli.l1_rpc_url.clone(),
            da_inbox: cli.da_inbox,
        })
    }

    // -----------------------------------------------------------------
    // Per-scenario client factories.
    // -----------------------------------------------------------------

    /// Spawn a fresh SRA: roll a random secp256k1 key, register it via
    /// [`AdminClient::register_sra`] (mask = [`SRA_PERMISSION_MASK`],
    /// active but non-rotation with a zero consensus identity — the
    /// testsuite SRA only needs to be active to submit records, and the
    /// M3 `AttestersRegistry` requires a non-zero `consensusKey` for
    /// rotation candidacy), and return an [`SraClient`] bound to it. The
    /// returned client is independent of `env.sra_zero` and can submit
    /// through the agents pool immediately.
    pub async fn new_sra(&self) -> eyre::Result<SraClient> {
        let secret = roll_random_key();
        let target_addr = derive_address(&secret)?;
        // Active-only attester: a zero consensus identity (rotation candidacy
        // would require a non-zero `consensus_key`, which this SRA doesn't need
        // — it only submits records).
        let is_rotation_candidate = false;
        let consensus_key = alloy_primitives::B256::ZERO;
        let p2p_addr = alloy_primitives::U256::ZERO;
        self.admin
            .register_sra(
                target_addr,
                SRA_PERMISSION_MASK,
                is_rotation_candidate,
                consensus_key,
                p2p_addr,
            )
            .await
            .map_err(|e| eyre::eyre!("register_sra: {e}"))?;
        // Wait for the register receipt to land. The `pending`
        // future inside `register_sra` returns the tx hash post-
        // broadcast; polling for receipt happens here so the
        // returned client can immediately submit.
        wait_for_active(&self.admin, target_addr, std::time::Duration::from_secs(30)).await?;
        SraClient::new(&self.rpc_url, self.chain_id, &secret)
    }

    /// Fresh [`ActorClient`] keyed by a random non-SRA wallet
    /// key — the canonical "end-user wallet" identity. The users
    /// lane is permissionless since psonet/pso-chain#13 (anti-spam
    /// = VDF + nullifier + block age, no registry gate), so this
    /// client's envelopes clear pool admission (S041); whether the
    /// inner call is *allowed* is the EVM contracts' job
    /// (`onlyActiveSRA` reverts — S003-S005, S030).
    pub fn new_actor(&self) -> eyre::Result<ActorClient> {
        let key = roll_random_key();
        ActorClient::new(&self.actor_rpc_url, self.chain_id, &key)
            .map_err(|e| eyre::eyre!("new_actor: {e}"))
    }

    /// Fresh [`ActorClient`] keyed by `&env.sra_zero`'s secret.
    /// Historically required to clear the users-lane SRA gate
    /// (removed in psonet/pso-chain#13); kept because the
    /// envelope-tampering / VDF-mismatch scenarios (S013-S017,
    /// S031-S032) were written against it and an SRA-keyed sender
    /// remains valid on the users lane.
    ///
    /// Today the only registered SRA whose secret material the
    /// env physically holds is SRA-0 (Hardhat #1) — that's why
    /// the signature is parameterless. If you need an actor
    /// client keyed by a fresh-`env.new_sra()`-returned client,
    /// build it directly via [`ActorClient::new`] from that
    /// `SraClient`'s constructor key (which scenarios persist
    /// themselves anyway, since `new_sra` is invoked inside the
    /// scenario body).
    pub fn new_actor_as_sra_zero(&self) -> eyre::Result<ActorClient> {
        ActorClient::new(&self.actor_rpc_url, self.chain_id, &self.sra_zero_key)
            .map_err(|e| eyre::eyre!("new_actor_as_sra_zero: {e}"))
    }

    /// Test-only: roll the chain's `DifficultyState` so the validator's
    /// `previous` slot holds the current `T` and `current` slot holds
    /// `new_difficulty`. Hits `pso_dev_advanceEpoch` on the actor RPC,
    /// which is gated server-side behind `PSO_DEV_RPC=1` — pso-chain
    /// must be spawned with that env var for this to succeed.
    ///
    /// Returns the `(current, previous, epoch_start_block)` triple the
    /// server reports back so the caller can assert on the rollover.
    pub async fn advance_epoch(&self, new_difficulty: u64) -> eyre::Result<(u64, u64, u64)> {
        use alloy_transport_http::reqwest::{Client, Url};
        use serde_json::{json, Value};
        let url: Url = self
            .actor_rpc_url
            .parse()
            .map_err(|e| eyre::eyre!("actor rpc url: {e}"))?;
        let body = json!({
            "jsonrpc": "2.0",
            "id":      1,
            "method":  "pso_dev_advanceEpoch",
            "params":  [new_difficulty],
        });
        let resp: Value = Client::new()
            .post(url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if let Some(err) = resp.get("error") {
            return Err(eyre::eyre!("pso_dev_advanceEpoch: {err}"));
        }
        let result = resp
            .get("result")
            .ok_or_else(|| eyre::eyre!("pso_dev_advanceEpoch: missing 'result' in {resp}"))?;
        let current = result["current"]
            .as_u64()
            .ok_or_else(|| eyre::eyre!("missing 'current' in {result}"))?;
        let previous = result["previous"]
            .as_u64()
            .ok_or_else(|| eyre::eyre!("missing 'previous' in {result}"))?;
        let epoch_start_block = result["epoch_start_block"]
            .as_u64()
            .ok_or_else(|| eyre::eyre!("missing 'epoch_start_block' in {result}"))?;
        Ok((current, previous, epoch_start_block))
    }
}

/// Roll a fresh 32-byte secp256k1 secret key from `OsRng`. The
/// statistical chance of producing zero or a value ≥ `n` is
/// negligible — every downstream constructor revalidates anyway.
pub(crate) fn roll_random_key() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// EVM address for a 32-byte secp256k1 secret key. Routes through
/// `k256::SecretKey` so we surface a typed error if the bytes don't
/// land in a valid scalar.
fn derive_address(secret: &[u8; 32]) -> eyre::Result<Address> {
    use alloy_signer_local::PrivateKeySigner;
    let _ = SecretKey::from_slice(secret).map_err(|e| eyre::eyre!("secret key invalid: {e}"))?;
    let signer = PrivateKeySigner::from_slice(secret)
        .map_err(|e| eyre::eyre!("secret key signer build: {e}"))?;
    Ok(signer.address())
}

/// Spin until `admin.is_active(addr)` returns true or `timeout`
/// elapses. Used internally by [`TestEnv::new_sra`] so the
/// returned client can submit immediately.
async fn wait_for_active(
    admin: &AdminClient,
    addr: Address,
    timeout: std::time::Duration,
) -> eyre::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if admin.is_active(addr).await.unwrap_or(false) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "timeout: admin.is_active({addr}) not true within {:?}",
                timeout
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

// -----------------------------------------------------------------
// SRA registry bootstrap — uses the `pso-chain-abi` registry interface
// directly (register + isActive). Kept as a standalone entry point so
// the env construction can run it *before* the `AdminClient` is built.
// -----------------------------------------------------------------

use pso_chain_abi::interfaces::IAttestersRegistry;

/// Register `target_secret_key`'s address with the SRA registry,
/// signing with `admin_secret_key` (the registry admin's secret key
/// — supplied by the CLI). No-op if the address is already active.
///
/// Pre-dates the public [`AdminClient`] surface and is kept as the
/// single entry point used by [`TestEnv::bootstrap_from_cli`]
/// because the env construction needs this to run *before* the
/// `AdminClient` itself is built (paranoia: the env contract
/// promises `sra_zero` is registered the moment the env returns,
/// so we want a known-good direct path that doesn't rely on the
/// admin abstraction).
pub async fn bootstrap_register_sra(
    rpc: &str,
    chain_id: u64,
    target_secret_key: &[u8; 32],
    admin_secret_key: &[u8; 32],
) -> eyre::Result<()> {
    let target_client =
        RpcHandle::connect_with_signer(rpc, chain_id, target_secret_key).map_err(map_rpc_err)?;
    let target_addr = target_client
        .signer_address()
        .ok_or_else(|| eyre::eyre!("SRA signer missing"))?;

    let read_provider = target_client.read_provider();
    let registry = IAttestersRegistry::new(SRA_REGISTRY, &read_provider);
    if registry.isActive(target_addr).call().await? {
        return Ok(());
    }

    let admin_client =
        RpcHandle::connect_with_signer(rpc, chain_id, admin_secret_key).map_err(map_rpc_err)?;
    let write_provider = admin_client.write_provider().map_err(map_rpc_err)?;
    let registry_w = IAttestersRegistry::new(SRA_REGISTRY, &write_provider);
    // Active-only attester with a zero consensus identity (see `new_sra`).
    let is_rotation_candidate = false;
    let consensus_key = alloy_primitives::B256::ZERO;
    let p2p_addr = alloy_primitives::U256::ZERO;
    let pending = registry_w
        .register(
            target_addr,
            SRA_PERMISSION_MASK,
            is_rotation_candidate,
            consensus_key,
            p2p_addr,
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await?;
    pending.get_receipt().await?;
    Ok(())
}

fn map_rpc_err(e: RpcError) -> eyre::Report {
    eyre::eyre!("rpc client: {e}")
}
