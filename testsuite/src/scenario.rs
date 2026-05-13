//! Scenario trait — the unit of e2e coverage.
//!
//! Each invariant we want enforced lives in a single
//! `scenarios/sNNN_*.rs` file as a `pub struct` implementing
//! [`Scenario`]. The CLI binary collects them via
//! [`scenarios::all`](crate::scenarios::all) and runs them in order,
//! producing a [`Report`].
//!
//! The trait is intentionally minimal: an id, a human-readable
//! description, and an async `run(&TestEnv)`. The shared
//! [`TestEnv`](crate::env::TestEnv) carries all the handles a
//! scenario needs (SRA client, actor client, bridge). Scenarios MUST
//! NOT spawn extra global state — anything new should land on the env
//! so the cleanup path stays uniform.

use std::path::Path;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;

use crate::env::TestEnv;

/// Single scenario contract.
///
/// Implementors return `Ok(())` for "invariant held" and any `Err`
/// for failure. The harness times `run` and records a
/// [`ScenarioResult`].
#[async_trait]
pub trait Scenario: Send + Sync {
    /// Short stable id, e.g. `"S001"`. Used as a key in CI reporting
    /// and to match against the `--only` / `--skip` filters.
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

// -----------------------------------------------------------------
// JSON projection. We deliberately don't `Serialize`-derive the live
// `ScenarioResult` (which holds an `eyre::Report` — not serialisable
// out of the box) and instead lower into a flat shape at print time.
// -----------------------------------------------------------------

/// Wire-shape of a single scenario row in the JSON report.
#[derive(Serialize)]
struct ScenarioRowJson<'a> {
    id: &'a str,
    description: &'a str,
    /// `"pass"` or `"fail"`.
    outcome: &'static str,
    duration_ms: u128,
    /// `None` on pass; `Some(error_text)` on fail.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Wire-shape of the report root.
#[derive(Serialize)]
struct ReportJson<'a> {
    total: usize,
    passed: usize,
    failed: usize,
    total_duration_ms: u128,
    results: Vec<ScenarioRowJson<'a>>,
}

/// Collected results from a runner invocation. Printable as
/// GitHub-flavoured markdown or one JSON document.
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

    /// Count of passed rows.
    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.passed()).count()
    }

    /// Aggregate wall-clock time.
    pub fn total_duration(&self) -> Duration {
        Duration::from_millis(self.results.iter().map(|r| r.duration_ms as u64).sum())
    }

    /// Build the JSON-shape rows (lazy — only when we're actually
    /// printing or writing JSON).
    fn json_rows(&self) -> Vec<ScenarioRowJson<'_>> {
        self.results
            .iter()
            .map(|r| ScenarioRowJson {
                id: r.id,
                description: r.description,
                outcome: if r.passed() { "pass" } else { "fail" },
                duration_ms: r.duration_ms,
                error: match &r.outcome {
                    Outcome::Pass => None,
                    Outcome::Fail(e) => Some(format!("{e}")),
                },
            })
            .collect()
    }

    fn to_json_doc(&self) -> ReportJson<'_> {
        ReportJson {
            total: self.results.len(),
            passed: self.passed(),
            failed: self.failed(),
            total_duration_ms: self.total_duration().as_millis(),
            results: self.json_rows(),
        }
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

    /// Emit the report as a single pretty-printed JSON document on
    /// stdout.
    pub fn print_json(&self) {
        let doc = self.to_json_doc();
        // `serde_json::to_string_pretty` only fails on user-supplied
        // serializer types; our shape is `derive(Serialize)` so the
        // unwrap is well-defined.
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("report JSON serialise failed: {e}"),
        }
    }

    /// Write the report to a file as pretty-printed JSON. Used by
    /// `--json-output PATH` regardless of the stdout report format.
    pub fn write_json(&self, path: &Path) -> eyre::Result<()> {
        let doc = self.to_json_doc();
        let s = serde_json::to_string_pretty(&doc)?;
        std::fs::write(path, s)
            .map_err(|e| eyre::eyre!("write {}: {e}", path.display()))?;
        Ok(())
    }
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}
