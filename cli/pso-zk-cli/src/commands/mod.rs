//! Command handler modules for the CLI.
//!
//! Each submodule implements one or more CLI command handlers:
//! - [`nft`]: `nft generate` command
//! - [`proof`]: `proof generate` and `proof verify` commands
//! - [`aggregate`]: `proof aggregate` command (SU-ownership aggregation
//!   proof for TributeDraft submission)

pub mod aggregate;
pub mod nft;
pub mod proof;
