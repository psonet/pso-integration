//! PSO L2 RPC client + high-level flow library.
//!
//! Two consumers — the SRA registrar and the wallet — both need to
//! make on-chain calls into the PSO predeployed contracts
//! ([`abi::SPENDING_RECORD`] / `SPENDING_RECORD_AMENDMENT` /
//! `SPENDING_UNIT` / `TRIBUTE_DRAFT` at `0x5200…0004..0007`). This
//! crate gives them:
//!
//! - [`client::L2Client`] — an alloy-based JSON-RPC handle with an
//!   optional in-memory signer.
//! - [`abi`] — inline `sol!` declarations for the four contracts.
//! - [`sra`] — flow functions the SRA registrar invokes.
//! - [`wallet`] — flow functions the wallet invokes.
//!
//! The two CLIs (`pso-sra-cli`, `pso-wallet-cli`) and the e2e test
//! crate (`pso-l2-e2e-tests`) all bottom out at the same library
//! surface. CLI is a thin argument-parsing layer; tests call the
//! library functions directly.

pub mod abi;
pub mod artifacts;
pub mod client;
pub mod error;
pub mod sra;
pub mod wallet;

pub use client::L2Client;
pub use error::L2ClientError;
