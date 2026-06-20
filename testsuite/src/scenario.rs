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
//! scenario needs (Attester client, actor client, bridge). Scenarios MUST
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
/// for failure. The harness:
///
/// 1. Calls [`Scenario::pre_start`] — optional setup the scenario
///    needs and which should NOT bleed into subsequent scenarios.
///    A failure here is reported with `outcome=fail` (the scenario
///    body never runs).
/// 2. Calls [`Scenario::run`] and times it; the duration recorded
///    on [`ScenarioResult`] reflects only this call.
/// 3. Calls [`Scenario::post_stop`] **regardless of run's outcome**
///    so state mutations made by the scenario can be released
///    before the next scenario starts. A post_stop failure is
///    logged (`scenario=Sxxx event=post_stop_failed`) but does
///    NOT downgrade a passing run — the scenario already passed
///    by the time the teardown ran.
#[async_trait]
pub trait Scenario: Send + Sync {
    /// Short stable id, e.g. `"S001"`. Used as a key in CI reporting
    /// and to match against the `--only` / `--skip` filters.
    fn id(&self) -> &'static str;

    /// Single-sentence description of the invariant the scenario
    /// enforces. Printed in the markdown report.
    fn description(&self) -> &'static str;

    /// Optional setup. Default no-op. Override to register
    /// auxiliary Attesters, allocate state, prime caches, etc. — any
    /// resource the scenario expects in place when [`Self::run`]
    /// starts. The env is the same handle [`Self::run`] receives;
    /// nothing magic is hidden between this and the body.
    async fn pre_start(&self, env: &TestEnv) -> eyre::Result<()> {
        let _ = env;
        Ok(())
    }

    /// Run the scenario against a shared environment. The harness
    /// guarantees the env is bootstrapped (and `pre_start` has
    /// completed successfully) before this is called.
    async fn run(&self, env: &TestEnv) -> eyre::Result<()>;

    /// Optional teardown. Default no-op. Override to release
    /// state mutations that would interfere with subsequent
    /// scenarios — e.g. revoke an Attester the scenario registered,
    /// drop nonces, etc. The harness calls this in **all** cases
    /// (success, failure, panic-after-await), so the body should
    /// be defensive about what may or may not actually be present.
    async fn post_stop(&self, env: &TestEnv) -> eyre::Result<()> {
        let _ = env;
        Ok(())
    }
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
    ///
    /// The `scenario.run` call is wrapped in an `info_span!` tagged
    /// with the scenario id. Every `tracing::info!` / `debug!` /
    /// `warn!` emitted from inside the scenario inherits that span,
    /// so the CI log can be sliced per-scenario after the fact by
    /// grepping the `scenario=` field. We also emit explicit
    /// `started` / `finished` events at the boundaries so a quick
    /// `grep '"finished"'` gives a per-scenario timing summary
    /// without parsing the markdown table.
    pub async fn time(scenario: &dyn Scenario, env: &TestEnv) -> Self {
        use tracing::Instrument;
        let id = scenario.id();
        let description = scenario.description();
        let span = tracing::info_span!("scenario", id = %id);

        let timed: (Outcome, u128) = async {
            tracing::info!(target: "pso_e2e::scenario", event = "started", scenario = id, description = description);

            // pre_start: a failure here is a scenario-level
            // failure — the body never runs, the duration field
            // captures only the time we spent in setup.
            let pre_start = Instant::now();
            if let Err(e) = scenario.pre_start(env).await {
                tracing::warn!(
                    target: "pso_e2e::scenario",
                    event = "pre_start_failed",
                    scenario = id,
                    error = %e,
                );
                let elapsed_ms = Instant::now().duration_since(pre_start).as_millis();
                // post_stop still runs so any half-built state
                // gets cleaned up; failures here are non-fatal.
                if let Err(te) = scenario.post_stop(env).await {
                    tracing::warn!(
                        target: "pso_e2e::scenario",
                        event = "post_stop_failed",
                        scenario = id,
                        error = %te,
                    );
                }
                return (Outcome::Fail(e), elapsed_ms);
            }

            // The duration we report is the body only — `run`
            // boundaries match the prior contract.
            let body_start = Instant::now();
            let result = scenario.run(env).await;
            let elapsed_ms = Instant::now().duration_since(body_start).as_millis();

            // post_stop runs unconditionally; failures are logged
            // but never downgrade a passing body.
            if let Err(te) = scenario.post_stop(env).await {
                tracing::warn!(
                    target: "pso_e2e::scenario",
                    event = "post_stop_failed",
                    scenario = id,
                    error = %te,
                );
            }

            match &result {
                Ok(()) => tracing::info!(
                    target: "pso_e2e::scenario",
                    event = "finished",
                    scenario = id,
                    outcome = "pass",
                    duration_ms = elapsed_ms as u64,
                ),
                Err(e) => tracing::warn!(
                    target: "pso_e2e::scenario",
                    event = "finished",
                    scenario = id,
                    outcome = "fail",
                    duration_ms = elapsed_ms as u64,
                    error = %e,
                ),
            }
            (
                match result {
                    Ok(()) => Outcome::Pass,
                    Err(e) => Outcome::Fail(e),
                },
                elapsed_ms,
            )
        }
        .instrument(span)
        .await;

        Self {
            id,
            description,
            duration_ms: timed.1,
            outcome: timed.0,
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
        std::fs::write(path, s).map_err(|e| eyre::eyre!("write {}: {e}", path.display()))?;
        Ok(())
    }

    /// Write the report to a file as a JUnit XML test report.
    ///
    /// One `<testsuite>` ("pso-e2e") with one `<testcase>` per
    /// scenario. The `name` field carries `"{id} - {description}"`
    /// so per-scenario rows in CI tooling read cleanly. Failed cases
    /// emit a `<failure message="...">` with the eyre report's
    /// `Display` rendering as the body text.
    ///
    /// Consumed by `dorny/test-reporter` (or any JUnit-aware CI
    /// dashboard) so each scenario shows up as its own green/red row
    /// in the GitHub Checks tab. Schema mirrors what Surefire / Jest
    /// produce; tested against `dorny/test-reporter@v1`.
    pub fn write_junit(&self, path: &Path) -> eyre::Result<()> {
        let xml = self.to_junit_xml();
        std::fs::write(path, xml).map_err(|e| eyre::eyre!("write {}: {e}", path.display()))?;
        Ok(())
    }

    /// Render the report as a JUnit XML string. Kept separate from
    /// `write_junit` so the unit tests can assert against it without
    /// a temp-file dance.
    pub fn to_junit_xml(&self) -> String {
        let total = self.results.len();
        let failures = self.failed();
        // Seconds with millisecond precision — Surefire convention.
        let total_seconds = self.total_duration().as_secs_f64();

        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str(&format!(
            "<testsuites name=\"pso-e2e\" tests=\"{total}\" failures=\"{failures}\" time=\"{total_seconds:.3}\">\n"
        ));
        out.push_str(&format!(
            "  <testsuite name=\"pso-e2e\" tests=\"{total}\" failures=\"{failures}\" errors=\"0\" skipped=\"0\" time=\"{total_seconds:.3}\">\n"
        ));
        for r in &self.results {
            let case_seconds = (r.duration_ms as f64) / 1000.0;
            let case_name = format!("{} - {}", r.id, r.description);
            match &r.outcome {
                Outcome::Pass => {
                    out.push_str(&format!(
                        "    <testcase classname=\"pso-e2e\" name=\"{}\" time=\"{:.3}\"/>\n",
                        xml_escape(&case_name),
                        case_seconds,
                    ));
                }
                Outcome::Fail(err) => {
                    let body = format!("{err}");
                    out.push_str(&format!(
                        "    <testcase classname=\"pso-e2e\" name=\"{}\" time=\"{:.3}\">\n",
                        xml_escape(&case_name),
                        case_seconds,
                    ));
                    // The `message` attribute carries a one-line
                    // summary (CI dashboards show it inline);
                    // the element body carries the full rendering.
                    let summary = body.lines().next().unwrap_or("scenario failed");
                    out.push_str(&format!(
                        "      <failure message=\"{}\" type=\"AssertionError\">{}</failure>\n",
                        xml_escape(summary),
                        xml_escape(&body),
                    ));
                    out.push_str("    </testcase>\n");
                }
            }
        }
        out.push_str("  </testsuite>\n");
        out.push_str("</testsuites>\n");
        out
    }
}

/// Minimal XML escaper. Only the five entities XML 1.0 requires —
/// JUnit consumers are forgiving about anything else.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}
