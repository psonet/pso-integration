//! Scenario trait — the unit of e2e coverage.
//!
//! Each invariant we want enforced lives in a single
//! `tests/scenarios/sNNN_*.rs` file as a `#[test]` (one-shot) and as
//! a struct implementing [`Scenario`] for the runner's bulk mode.
//!
//! The trait is intentionally minimal: an id, a human-readable
//! description, and an async `run(&TestEnv)`. The shared
//! [`TestEnv`](crate::env::TestEnv) carries all the handles a
//! scenario needs (SRA client, actor client, bridge). Scenarios MUST
//! NOT spawn extra global state — anything new should land on the env
//! so the cleanup path stays uniform.

use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::env::TestEnv;

/// Single scenario contract.
///
/// Implementors return `Ok(())` for "invariant held" and any `Err`
/// for failure. The harness times `run` and records a
/// [`ScenarioResult`].
#[async_trait]
pub trait Scenario: Send + Sync {
    /// Short stable id, e.g. `"S001"`. Used as a key in CI reporting
    /// and to match against the file-per-scenario layout.
    fn id(&self) -> &'static str;

    /// Single-sentence description of the invariant the scenario
    /// enforces. Printed in the markdown report.
    fn description(&self) -> &'static str;

    /// Run the scenario against a shared environment. The harness
    /// guarantees the env is bootstrapped before this is called.
    async fn run(&self, env: &TestEnv) -> eyre::Result<()>;
}

/// Outcome of a single scenario run.
pub enum Outcome {
    /// Invariant held.
    Pass,
    /// Invariant violated or harness-level error. The inner report
    /// is what the scenario returned (or what the harness produced
    /// before / after calling it).
    Fail(eyre::Report),
}

/// Result row collected by the runner. Cheap to build and printable
/// in a single line of markdown.
pub struct ScenarioResult {
    /// Mirror of [`Scenario::id`].
    pub id: &'static str,
    /// Mirror of [`Scenario::description`].
    pub description: &'static str,
    /// Wall-clock duration of the scenario's `run` call.
    pub duration_ms: u128,
    /// Pass/fail with the error if any.
    pub outcome: Outcome,
}

impl ScenarioResult {
    /// Time the scenario, capture the outcome, and assemble a row.
    pub async fn time(scenario: &dyn Scenario, env: &TestEnv) -> Self {
        let start = Instant::now();
        let outcome = match scenario.run(env).await {
            Ok(()) => Outcome::Pass,
            Err(e) => Outcome::Fail(e),
        };
        Self {
            id: scenario.id(),
            description: scenario.description(),
            duration_ms: Instant::now().duration_since(start).as_millis(),
            outcome,
        }
    }

    /// Returns `true` iff the scenario passed.
    pub fn passed(&self) -> bool {
        matches!(self.outcome, Outcome::Pass)
    }
}

/// Collected results from a runner invocation. Printable as
/// GitHub-flavoured markdown for CI artifacts.
pub struct Report {
    /// In submission order.
    pub results: Vec<ScenarioResult>,
}

impl Report {
    /// Empty report.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Append a row.
    pub fn push(&mut self, r: ScenarioResult) {
        self.results.push(r);
    }

    /// Count of failed rows.
    pub fn failed(&self) -> usize {
        self.results.iter().filter(|r| !r.passed()).count()
    }

    /// Aggregate wall-clock time.
    pub fn total_duration(&self) -> Duration {
        Duration::from_millis(self.results.iter().map(|r| r.duration_ms as u64).sum())
    }

    /// Emit a markdown table on stdout. Designed to be pasted into
    /// CI-published summary blocks.
    pub fn print_markdown(&self) {
        let passed = self.results.len() - self.failed();
        println!(
            "\n## PSO L2 e2e scenario report ({passed}/{} passing, total {} ms)\n",
            self.results.len(),
            self.total_duration().as_millis()
        );
        println!("| id | outcome | ms | description |");
        println!("| --- | --- | --- | --- |");
        for r in &self.results {
            let (mark, detail) = match &r.outcome {
                Outcome::Pass => ("PASS", String::new()),
                Outcome::Fail(e) => ("FAIL", format!(" — {e}")),
            };
            println!(
                "| {id} | {mark} | {ms} | {desc}{detail} |",
                id = r.id,
                mark = mark,
                ms = r.duration_ms,
                desc = r.description,
                detail = detail,
            );
        }
        println!();
    }
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}
