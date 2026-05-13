//! Bulk-mode scenario runner.
//!
//! Bootstraps a single shared [`TestEnv`] and runs every scenario in
//! a deterministic order. Prints a markdown report; panics if any
//! scenario failed.
//!
//! Use this when you want one-shot coverage:
//!
//! ```text
//! cargo test -p pso-l2-e2e-tests --test runner -- --ignored
//! ```
//!
//! Per-scenario tests live under `tests/scenarios/`. The runner
//! pulls in each scenario's module via `#[path]` so we don't have
//! to duplicate `Scenario` impls.

#[path = "scenarios/s001_happy_flow.rs"]
mod s001_mod;
#[path = "scenarios/s002_sra_cannot_td_via_agents_pool.rs"]
mod s002_mod;
#[path = "scenarios/s003_wallet_cannot_register_sr.rs"]
mod s003_mod;
#[path = "scenarios/s004_wallet_cannot_register_ar.rs"]
mod s004_mod;
#[path = "scenarios/s005_wallet_cannot_mint_su.rs"]
mod s005_mod;
#[path = "scenarios/s006_sra_cannot_use_actor_endpoint.rs"]
mod s006_mod;
#[path = "scenarios/s007_sr_duplicate_id_rejected.rs"]
mod s007_mod;
#[path = "scenarios/s008_sr_id_zero_rejected.rs"]
mod s008_mod;
#[path = "scenarios/s009_su_with_foreign_sr_rejected.rs"]
mod s009_mod;
#[path = "scenarios/s010_su_double_spend_rejected.rs"]
mod s010_mod;
#[path = "scenarios/s011_su_with_nonexistent_sr_rejected.rs"]
mod s011_mod;
#[path = "scenarios/s012_td_empty_array_rejected.rs"]
mod s012_mod;

use pso_l2_e2e_tests::{Report, Scenario, ScenarioResult, TestEnv};

/// Collect every scenario in canonical order. Listed top-to-bottom so
/// the printed report matches the spec table.
fn all_scenarios() -> Vec<Box<dyn Scenario>> {
    vec![
        Box::new(s001_mod::S001),
        Box::new(s002_mod::S002),
        Box::new(s003_mod::S003),
        Box::new(s004_mod::S004),
        Box::new(s005_mod::S005),
        Box::new(s006_mod::S006),
        Box::new(s007_mod::S007),
        Box::new(s008_mod::S008),
        Box::new(s009_mod::S009),
        Box::new(s010_mod::S010),
        Box::new(s011_mod::S011),
        Box::new(s012_mod::S012),
    ]
}

// Multi-thread runtime so the bridge's spawn_blocking-wrapped bb FFI
// calls don't share an OS thread with the async polling loop — bb 5.x
// behaves unevenly on current_thread when control hops in and out of
// the blocking pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running PSO L2 node — opt-in via `cargo test -- --ignored`"]
#[serial_test::serial]
async fn run_all_scenarios() -> eyre::Result<()> {
    pso_l2_e2e_tests::env::init_tracing();
    let env = TestEnv::shared().await?;

    let scenarios = all_scenarios();
    let mut report = Report::new();
    for sc in &scenarios {
        let row = ScenarioResult::time(sc.as_ref(), env).await;
        report.push(row);
    }
    report.print_markdown();
    let failed = report.failed();
    if failed > 0 {
        panic!(
            "{failed}/{total} scenarios failed",
            total = report.results.len()
        );
    }
    Ok(())
}
