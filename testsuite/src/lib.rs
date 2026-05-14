//! Scenario-driven e2e framework for the PSO L2.
//!
//! Powers the `pso-e2e` binary. Two client surfaces drive the chain:
//!
//! - [`SraClient`](clients::sra::SraClient) — agents-pool side. Wraps
//!   `pso-l2-client::sra` and posts via the standard EL JSON-RPC at
//!   `:19545`. The pool admits a tx iff `from` is in the SRA registry
//!   AND `(to, selector)` is in the agents-pool allowlist.
//! - [`ActorClient`](clients::actor::ActorClient) — users-pool side.
//!   Posts PSO-magic-prefixed (`0xCAFED00D`) calldata to the actor
//!   RPC at `:8546` with a real MinRoot VDF proof bound to
//!   `SHA-256(signer || nonce || submitted_block || chain_id)`.
//!
//! Each scenario implements [`Scenario`](scenario::Scenario), reads a
//! shared [`TestEnv`](env::TestEnv), and asserts a typed
//! [`PsoContractError`](errors::PsoContractError) variant on the
//! rejection paths. The CLI binary owns the tokio runtime; we no
//! longer ship the `OnceCell`-backed "shared env" the cargo-test
//! version used.
//!
//! # Module surface
//!
//! All public modules are re-exported under the crate root so
//! scenarios can write `use pso_e2e_testsuite::{...}` without
//! descending into the module tree.

pub mod bridge;
pub mod cli;
pub mod clients;
pub mod data;
pub mod env;
pub mod hardhat;
pub mod scenario;
pub mod scenarios;

pub use bridge::{spawn_sra_loop, Bridge, BridgeError, SuMintArgs, SuMintReceipt, SuMintRequest};
pub use cli::{init_tracing, parse_hex32, Cli, ReportFormat};
pub use clients::actor::{ActorClient, ActorClientError};
pub use clients::sra::{into_pso_error, SraClient};
pub use env::TestEnv;
// `PsoContractError` + the decoder primitives now live in
// `pso-l2-client::contract_errors` so non-test clients (mobile FFI,
// future Rust integrators) can decode contract reverts with the
// same typed enum. Re-export at the testsuite root to keep
// scenarios' `use crate::PsoContractError` style stable.
pub use hardhat::{signer_address, signer_key, HARDHAT_KEYS};
pub use pso_l2_client::contract_errors::{decode_text, PsoContractError};
pub use scenario::{Outcome, Report, Scenario, ScenarioResult};

// -----------------------------------------------------------------
// Constants kept at the crate root for ergonomic scenario imports.
// The CLI overrides these via `--rpc-url` / `--actor-rpc-url` /
// `--chain-id`; the defaults match pso-chain's `--dev` genesis.
// -----------------------------------------------------------------

/// PSO devnet chain id. Mirror of `pso-chain`'s `--dev` genesis.
pub const DEVNET_CHAIN_ID: u64 = 19_280_501;

/// Default agents-pool RPC endpoint.
pub const DEFAULT_AGENTS_RPC: &str = "http://127.0.0.1:19545";

/// Default actor-pool RPC endpoint.
pub const DEFAULT_ACTOR_RPC: &str = "http://127.0.0.1:8546";
