//! Scenario-driven e2e framework for the PSO L2.
//!
//! Powers the `pso-e2e` binary. Two client surfaces drive the chain:
//!
//! - [`AttesterClient`](clients::attester::AttesterClient) — agents-pool side. Submits
//!   SR/AR/SU calls (built directly on the `pso-chain-abi` interfaces +
//!   the testsuite's own [`RpcHandle`](clients::rpc::RpcHandle)) via the
//!   standard EL JSON-RPC at `:19545`. The pool admits a tx iff `from`
//!   is in the attesters registry AND `(to, selector)` is in the
//!   agents-pool allowlist.
//! - [`ActorClient`](clients::actor::ActorClient) — users-pool side.
//!   Posts `0x76`-enveloped calldata to the actor RPC at `:8546` with a
//!   real MinRoot VDF proof bound to
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

pub mod bls_verify;
pub mod bridge;
pub mod cli;
pub mod clients;
pub mod data;
pub mod env;
pub mod hardhat;
pub mod scenario;
pub mod scenarios;

pub use bridge::{
    spawn_attester_loop, Bridge, BridgeError, SuMintArgs, SuMintReceipt, SuMintRequest,
};
pub use cli::{init_tracing, parse_hex32, Cli, ReportFormat};
pub use clients::actor::{ActorClient, ActorClientError};
pub use clients::attester::AttesterClient;
pub use clients::contract_errors::{decode_text, into_pso_error, PsoContractError};
pub use env::TestEnv;
// `PsoContractError` + the decoder primitives are owned by the
// testsuite's `clients::contract_errors` module. Re-export at the crate
// root to keep scenarios' `use crate::PsoContractError` style stable.
pub use hardhat::{signer_address, signer_key, HARDHAT_KEYS};
pub use scenario::{Outcome, Report, Scenario, ScenarioResult};

// -----------------------------------------------------------------
// Constants kept at the crate root for ergonomic scenario imports.
// The CLI overrides these via `--rpc-url` / `--actor-rpc-url` /
// `--chain-id`; the defaults match pso-chain's `--dev` genesis.
// -----------------------------------------------------------------

/// Sort a `uint256` id vector into the canonical set the chain now `require`s
/// on submit (strictly-ascending `suIds`/`srIds`/`arIds`) and the entity hash
/// folds (pso-protocol 0.9 hashes `Vec<T>` fields as sorted sets). For the
/// canonical (`< modulus`) ids these sets hold, a plain `U256` ascending sort
/// equals field-value order, so `sort` + `dedup` produces exactly that order.
pub fn sorted_unique_u256(mut v: Vec<alloy_primitives::U256>) -> Vec<alloy_primitives::U256> {
    v.sort();
    v.dedup();
    v
}

/// PSO devnet chain id. Mirror of `pso-chain`'s `--dev` genesis.
pub const DEVNET_CHAIN_ID: u64 = 19_280_501;

/// Default agents-pool RPC endpoint.
pub const DEFAULT_AGENTS_RPC: &str = "http://127.0.0.1:19545";

/// Default actor-pool RPC endpoint.
pub const DEFAULT_ACTOR_RPC: &str = "http://127.0.0.1:8546";
