//! Mobile-friendly UniFFI wrapper for PSO ZK proof generation.
//!
//! Provides a flat API for React Native clients to generate ownership
//! and full (ownership + Merkle inclusion) zero-knowledge proofs for
//! TributeDraft and SpendingUnit NFTs.
//!
//! # Architecture
//!
//! This crate is a thin FFI boundary layer. All cryptographic logic
//! delegates to the existing workspace crates:
//! - `pso-protocol` — consensus-binding primitives and witness types
//! - `pso-zk-circuit-noir` — Noir/Barretenberg proof generation
//! - `pso-nft` — domain NFT types (TributeDraft, SpendingUnit)
//!
//! Circuit bytecodes are embedded at compile time. Circuits are
//! initialized lazily on first use.

mod api;
mod circuits;
mod convert;
mod types;

#[cfg(feature = "dev-tools")]
mod dev_tools;

pub use api::*;
pub use types::*;

#[cfg(feature = "dev-tools")]
pub use dev_tools::*;

uniffi::setup_scaffolding!();
