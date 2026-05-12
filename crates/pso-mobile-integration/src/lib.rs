//! Mobile-friendly UniFFI wrapper for PSO wallet operations.
//!
//! Provides a flat API for React Native clients to:
//! - Generate ownership and full (ownership + Merkle inclusion)
//!   zero-knowledge proofs for TributeDraft and SpendingUnit NFTs
//!   (see [`api`]).
//! - Compute and verify MinRoot VDF proofs that gate Users-pool
//!   transaction submission (see [`vdf`]).
//!
//! # Architecture
//!
//! This crate is a thin FFI boundary layer. All cryptographic logic
//! delegates to the existing workspace crates:
//! - `pso-protocol` — consensus-binding primitives and witness types
//! - `pso-zk-circuit-noir` — Noir/Barretenberg proof generation
//! - `pso-nft` — domain NFT types (TributeDraft, SpendingUnit)
//! - `pso-vdf` — MinRoot VDF for Users-pool transaction gating
//!
//! Circuit bytecodes are embedded at compile time. Circuits are
//! initialized lazily on first use.

mod api;
mod circuits;
mod convert;
mod types;
mod vdf;

#[cfg(feature = "dev-tools")]
mod dev_tools;

pub use api::*;
pub use types::*;
pub use vdf::*;

#[cfg(feature = "dev-tools")]
pub use dev_tools::*;

uniffi::setup_scaffolding!();
