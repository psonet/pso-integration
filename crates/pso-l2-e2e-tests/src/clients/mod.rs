//! Two client surfaces, one per pool.
//!
//! - [`sra`] — agents-pool side: standard EL JSON-RPC at `:19545`.
//!   Wraps `pso-l2-client::sra` so test code reads as
//!   `env.sra.register_spending_record(...)` without dragging the
//!   underlying `L2Client` shape into every scenario.
//! - [`actor`] — users-pool side: PSO-magic-prefixed calldata posted
//!   to `:8546`, carrying a real MinRoot VDF proof.
//! - [`envelope`] — pure byte-layout helpers for the
//!   `[magic|nullifier|vdf_*|submitted_block|inner]` header. Shared
//!   between the client and any future direct-RPC tests.

pub mod actor;
pub mod envelope;
pub mod sra;
