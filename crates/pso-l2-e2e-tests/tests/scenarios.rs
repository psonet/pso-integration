//! Integration-test entry point for the per-scenario `#[test]` set.
//!
//! Cargo compiles each top-level `tests/*.rs` file as a separate
//! binary; sub-modules under `tests/scenarios/` are picked up via
//! this stub which simply re-exports them. The `#[test]` functions
//! declared in each scenario file are discovered through normal
//! `mod`-walking; running e.g.
//!
//! ```text
//! cargo test -p pso-l2-e2e-tests --test scenarios -- --ignored s007
//! ```
//!
//! filters to a single scenario.
//!
//! Bulk-mode (one bootstrap, all scenarios) is in `tests/runner.rs`.

mod scenarios {
    pub mod s001_happy_flow;
    pub mod s002_sra_cannot_td_via_agents_pool;
    pub mod s003_wallet_cannot_register_sr;
    pub mod s004_wallet_cannot_register_ar;
    pub mod s005_wallet_cannot_mint_su;
    pub mod s006_sra_cannot_use_actor_endpoint;
    pub mod s007_sr_duplicate_id_rejected;
    pub mod s008_sr_id_zero_rejected;
    pub mod s009_su_with_foreign_sr_rejected;
    pub mod s010_su_double_spend_rejected;
    pub mod s011_su_with_nonexistent_sr_rejected;
    pub mod s012_td_empty_array_rejected;
}
