//! Two client surfaces, one per pool, plus the shared client plumbing.
//!
//! - [`sra`] — agents-pool side: standard EL JSON-RPC at `:19545`.
//!   Test code reads as `env.sra.register_spending_record(...)` without
//!   dragging the underlying [`rpc::RpcHandle`] shape into every scenario.
//! - [`actor`] — users-pool side: PSO `0x76`-enveloped calldata posted
//!   to `:8546`, carrying a real MinRoot VDF proof.
//! - [`admin`] — Hardhat #0: the AttestersRegistry-mutating surface.
//! - [`envelope`] — pure byte-layout helpers for the `0x76`
//!   VdfProtectedTransaction envelope.
//! - [`rpc`] — the small alloy provider+signer handle the SRA/admin
//!   clients are built on (the testsuite owns this; there is no shared
//!   `l2-client` crate anymore).
//! - [`contract_errors`] — the typed Solidity revert decoder
//!   ([`PsoContractError`](contract_errors::PsoContractError)).
//! - [`contracts`] — inline `sol!` bindings for the two contracts
//!   `pso-chain-abi` does not carry (SequencerEpoch, SlashingVerifier).

pub mod actor;
pub mod admin;
pub mod contract_errors;
pub mod contracts;
pub mod envelope;
pub mod rpc;
pub mod sra;
