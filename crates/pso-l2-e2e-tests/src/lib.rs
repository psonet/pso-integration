//! Scenario-driven e2e framework for PSO L2.
//!
//! The crate's `tests/` tree exercises the deployed pso-chain devnet by
//! routing operations through two client surfaces:
//!
//! - [`SraClient`](clients::sra::SraClient) — agents-pool side. Wraps
//!   `pso-l2-client::sra` and posts via the standard EL JSON-RPC at
//!   `:19545`. Authentication is by sender address: the validator
//!   admits txs whose `from` is in the SRA registry AND whose
//!   `(to, selector)` is in the agents-pool allowlist.
//! - [`ActorClient`](clients::actor::ActorClient) — users-pool side.
//!   Posts PSO-magic-prefixed (`0xCAFED00D`) calldata to the actor
//!   RPC at `:8546`. Carries a real MinRoot VDF proof bound to
//!   `SHA-256(signer || nonce || submitted_block || chain_id)`.
//!
//! Each scenario implements [`Scenario`](scenario::Scenario), reads a
//! shared [`TestEnv`](env::TestEnv), and asserts a typed
//! [`PsoContractError`](errors::PsoContractError) variant on the
//! rejection paths. The shared env is built once via
//! [`TestEnv::shared`](env::TestEnv::shared) and reused across the
//! `#[serial_test::serial]`-gated test bodies.
//!
//! # Re-exports
//!
//! The module surface is exposed under the crate root so individual
//! `tests/scenarios/*.rs` files can write
//! `use pso_l2_e2e_tests::{...}` without descending into the module
//! tree. Each scenario then matches against `PsoContractError::*`
//! variants directly.

pub mod bridge;
pub mod clients;
pub mod data;
pub mod env;
pub mod errors;
pub mod hardhat;
pub mod scenario;

pub use bridge::{spawn_sra_loop, Bridge, BridgeError, SuMintArgs, SuMintReceipt, SuMintRequest};
pub use clients::actor::{ActorClient, ActorClientError};
pub use clients::sra::{into_pso_error, SraClient};
pub use env::TestEnv;
pub use errors::{decode_text, PsoContractError};
pub use hardhat::{signer_address, signer_key, HARDHAT_KEYS};
pub use scenario::{Outcome, Report, Scenario, ScenarioResult};

// -----------------------------------------------------------------
// Constants kept at the crate root for ergonomic test imports.
// -----------------------------------------------------------------

/// PSO devnet chain id. Mirror of `pso-chain`'s `--dev` genesis.
pub const DEVNET_CHAIN_ID: u64 = 19_280_501;

/// Default agents-pool RPC endpoint. Override via `PSO_L2_RPC`.
pub const DEFAULT_AGENTS_RPC: &str = "http://127.0.0.1:19545";

/// Default actor-pool RPC endpoint. Override via `PSO_L2_ACTOR_RPC`.
pub const DEFAULT_ACTOR_RPC: &str = "http://127.0.0.1:8546";

/// Env var the e2e harness reads for the agents-pool RPC URL.
pub const PSO_L2_RPC_ENV: &str = "PSO_L2_RPC";

/// Env var the e2e harness reads for the actor-pool RPC URL.
pub const PSO_L2_ACTOR_RPC_ENV: &str = "PSO_L2_ACTOR_RPC";

/// Fetch the agents-pool RPC URL.
pub fn rpc_url() -> String {
    std::env::var(PSO_L2_RPC_ENV).unwrap_or_else(|_| DEFAULT_AGENTS_RPC.to_string())
}

/// Fetch the actor-pool RPC URL.
pub fn actor_rpc_url() -> String {
    std::env::var(PSO_L2_ACTOR_RPC_ENV).unwrap_or_else(|_| DEFAULT_ACTOR_RPC.to_string())
}
