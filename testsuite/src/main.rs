//! `pso-e2e` — CLI entry point.
//!
//! Parses CLI args, bootstraps a single tokio multi-thread runtime,
//! drives every scenario, and exits with a structured status code:
//!
//! - `0` → all scenarios passed.
//! - `1` → at least one scenario failed.
//! - `2` → bootstrap or arg-parse error (clap / eyre print to
//!   stderr; nothing else to do at this layer).
//!
//! pso-chain CI packages this binary into a Docker image; see
//! `testsuite/Dockerfile`.

use std::process::ExitCode;

use clap::Parser;

use pso_e2e_testsuite::cli::{init_tracing, Cli, ReportFormat};
use pso_e2e_testsuite::scenario::{Report, Scenario, ScenarioResult};
use pso_e2e_testsuite::{scenarios, TestEnv};

fn main() -> ExitCode {
    // Parse CLI first so `--help` / `--version` short-circuit before
    // we touch the network. clap returns its own `ExitCode::from(2)`
    // on parse failure; mirror that for our own bootstrap errors.
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // `e.exit()` consumes the error and process::exit's with
            // clap's chosen status. For -h / -V that's 0; for parse
            // failure it's 2. Either path leaves the runtime
            // un-spawned, which is what we want.
            e.exit();
        }
    };

    init_tracing(cli.verbose);

    // Multi-thread runtime so the bridge's spawn_blocking-wrapped bb
    // FFI calls don't share an OS thread with the async polling loop
    // — bb 5.x behaves unevenly on current_thread when control hops
    // in and out of the blocking pool.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: build tokio runtime: {e}");
            return ExitCode::from(2);
        }
    };

    let failed = match runtime.block_on(run(cli)) {
        Ok(count) => count,
        Err(e) => {
            // Bootstrap / arg-parse / file-write error. eyre's
            // Display prints a multi-line trace; let it through.
            eprintln!("Error: {e:?}");
            return ExitCode::from(2);
        }
    };

    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Async body. Returns the count of failed scenarios (0 ⇒ all
/// passed). Any error from this function is a bootstrap-level
/// problem (not a scenario assertion failure) and exits 2.
async fn run(cli: Cli) -> eyre::Result<usize> {
    // `--list` short-circuits before we touch the chain: enumerate
    // the compiled-in scenarios (post-filter, so `--only` /
    // `--skip` preview is meaningful) and exit 0.
    let all = scenarios::all();
    let mut filtered = apply_filters(all, cli.only.as_deref(), cli.skip.as_deref());

    // S045 (DA batch committed) + S046 (cert-backed inclusion) read the L1
    // DaInbox. Without `--l1-rpc-url` there's nothing to assert against, so drop
    // them rather than fail — consumers that don't expose their L1 run the rest
    // of the suite unaffected. (The harness that wires DA passes --l1-rpc-url +
    // --da-inbox.)
    if cli.l1_rpc_url.is_none() {
        let before = filtered.len();
        filtered.retain(|s| s.id() != "S045" && s.id() != "S046");
        if filtered.len() != before {
            tracing::info!("S045/S046 skipped: --l1-rpc-url not provided (no DA inbox to read)");
        }
    }

    if cli.list {
        println!("{} compiled-in scenario(s):", filtered.len());
        for sc in &filtered {
            println!("  {}  {}", sc.id(), sc.description());
        }
        return Ok(0);
    }

    let env = TestEnv::bootstrap_from_cli(&cli).await?;

    let mut report = Report::new();
    for sc in &filtered {
        report.push(ScenarioResult::time(sc.as_ref(), &env).await);
    }

    match cli.report {
        ReportFormat::Markdown => report.print_markdown(),
        ReportFormat::Json => report.print_json(),
    }
    if let Some(path) = &cli.json_output {
        report.write_json(path)?;
    }
    if let Some(path) = &cli.junit_output {
        report.write_junit(path)?;
    }

    // Flush the bridge so its tracing line ("loop exiting") drains
    // before we exit — keeps `-vv` logs tidy.
    drop(env);

    Ok(report.failed())
}

/// Apply `--only` / `--skip` comma-separated substring filters to
/// the scenario list. Filtering is case-sensitive — scenario ids
/// (`"S001"`, ...) are stable upper-case strings.
fn apply_filters(
    scenarios: Vec<Box<dyn Scenario>>,
    only: Option<&str>,
    skip: Option<&str>,
) -> Vec<Box<dyn Scenario>> {
    let only_tokens: Vec<&str> = only
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let skip_tokens: Vec<&str> = skip
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    scenarios
        .into_iter()
        .filter(|sc| {
            let id = sc.id();
            let keep_only = only_tokens.is_empty() || only_tokens.iter().any(|t| id.contains(t));
            let keep_skip = !skip_tokens.iter().any(|t| id.contains(t));
            keep_only && keep_skip
        })
        .collect()
}
