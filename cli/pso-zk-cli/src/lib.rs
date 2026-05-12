//! PSO ZK Proof CLI library.
//!
//! Re-exports the public types and command handlers for use in integration tests.
//! The binary entry point is in `main.rs`.

pub mod commands;
pub mod display;
pub mod types;

// Re-export CLI argument types for integration tests.
pub use crate::commands::nft::handle_nft_generate;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// PSO ZK Proof CLI -- generate NFTs, create and verify zero-knowledge proofs.
#[derive(Parser)]
#[command(name = "pso-zk-cli", version, about, propagate_version = true)]
pub struct Cli {
    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level command groups.
#[derive(Subcommand)]
pub enum Commands {
    /// NFT data operations
    Nft {
        /// NFT subcommand to execute.
        #[command(subcommand)]
        action: NftCommands,
    },
    /// Zero-knowledge proof operations
    Proof {
        /// Proof subcommand to execute.
        #[command(subcommand)]
        action: ProofCommands,
    },
}

/// Subcommands for NFT operations.
#[derive(Subcommand)]
pub enum NftCommands {
    /// Generate random NFT data and save to JSON
    Generate {
        /// NFT type to generate
        #[arg(short = 't', long, default_value = "tribute-draft")]
        nft_type: NftType,

        /// Output JSON file path
        #[arg(short, long)]
        output: PathBuf,
    },
}

/// Subcommands for proof operations.
#[derive(Subcommand)]
pub enum ProofCommands {
    /// Generate a zero-knowledge proof from NFT data
    Generate {
        /// Path to the NFT JSON file (from `nft generate`)
        #[arg(short, long)]
        nft: PathBuf,

        /// Path to the compiled circuit JSON file
        #[arg(short, long)]
        circuit: PathBuf,

        /// Proof mode: "full" (ownership + Merkle) or "ownership" (ownership only)
        #[arg(short, long, default_value = "full")]
        mode: ProofMode,

        /// Output JSON file path for the generated proof
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify a previously generated proof
    Verify {
        /// Path to the proof JSON file (from `proof generate`)
        #[arg(short, long)]
        proof: PathBuf,

        /// Path to the compiled circuit JSON file
        #[arg(short, long)]
        circuit: PathBuf,
    },
    /// Generate an SU-ownership aggregation proof for TributeDraft
    /// submission. Reads an input JSON describing the wallet's
    /// secret key, the aggregated SU slots, and the binding-hash
    /// parameters (sender, tribute_draft_id, chain_id), then writes
    /// the canonical proof bytes to the output file.
    Aggregate {
        /// Path to the aggregation input JSON. See
        /// `commands::aggregate::AggregationInput` for the schema.
        #[arg(short, long)]
        input: PathBuf,

        /// Output JSON file path for the generated proof
        #[arg(short, long)]
        output: PathBuf,
    },
}

/// NFT type selector.
#[derive(Clone, ValueEnum)]
pub enum NftType {
    /// Generate a TributeDraft NFT
    TributeDraft,
    /// Generate a SpendingUnit NFT
    SpendingUnit,
}

/// Proof mode selector.
#[derive(Clone, ValueEnum)]
pub enum ProofMode {
    /// Full proof: ownership + Merkle inclusion
    Full,
    /// Ownership-only proof
    Ownership,
}
