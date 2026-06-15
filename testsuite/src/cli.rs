//! Command-line interface for the `pso-e2e` binary.
//!
//! Endpoints and signing keys are CLI-only by design — there are no
//! env-var fallbacks. pso-chain CI invokes the binary with explicit
//! `--admin-key` / `--sra-key` / `--rpc-url` arguments derived from
//! the devnet container it spun up.
//!
//! See the crate `README.md` for usage examples; the doc-comments on
//! each field carry the same intent in machine-readable form.

use std::path::PathBuf;

use clap::Parser;
use clap::ValueEnum;

use crate::{DEFAULT_ACTOR_RPC, DEFAULT_AGENTS_RPC, DEVNET_CHAIN_ID};

/// Report flavour the binary prints on stdout.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum ReportFormat {
    /// GitHub-flavoured markdown table. Default — pastes cleanly into
    /// CI summary blocks.
    Markdown,
    /// One-JSON-object-per-line stream. Easier to ingest from a
    /// machine-side aggregator.
    Json,
}

/// Top-level CLI flags. See the field-level doc-comments for what
/// each one binds to.
#[derive(Debug, Parser)]
#[command(
    name = "pso-e2e",
    about = "End-to-end test harness for the PSO L2 (agents pool + actor pool).",
    long_about = "Drives the SRA + Wallet round-trip plus a suite of \
                  negative-path invariants against a live PSO L2 devnet. \
                  Exits 0 on full pass, 1 on at least one scenario \
                  failure, 2 on bootstrap / arg-parse error. Use \
                  `--list` to enumerate the compiled-in scenarios."
)]
pub struct Cli {
    /// Agents-pool JSON-RPC endpoint. The SRA-key signer submits SR /
    /// AR / SU contract calls through this URL.
    #[arg(long, default_value = DEFAULT_AGENTS_RPC)]
    pub rpc_url: String,

    /// Actor-pool JSON-RPC endpoint. PSO-magic-prefixed transactions
    /// (wallet flows) are POSTed here.
    #[arg(long, default_value = DEFAULT_ACTOR_RPC)]
    pub actor_rpc_url: String,

    /// L2 chain ID. Defaults to the devnet genesis (19_280_501).
    #[arg(long, default_value_t = DEVNET_CHAIN_ID)]
    pub chain_id: u64,

    /// Hex secret key of the SRARegistry admin (0x-prefixed or bare).
    /// Used to register the SRA signer and any per-scenario auxiliary
    /// SRAs. Not required with `--list`.
    #[arg(long, value_parser = parse_hex32, required_unless_present = "list")]
    pub admin_key: Option<[u8; 32]>,

    /// Hex secret key of the primary SRA. The suite registers this
    /// address with the registry (if not already active) and uses it
    /// for every agents-pool tx. Agents are otherwise dynamic — the
    /// suite generates auxiliary keys at runtime. Not required with
    /// `--list`.
    #[arg(long, value_parser = parse_hex32, required_unless_present = "list")]
    pub sra_key: Option<[u8; 32]>,

    /// Wallet (actor-pool) signer. Optional; if omitted the suite
    /// rolls a fresh key per run. Useful only when CI wants stable
    /// addresses across reruns.
    #[arg(long, value_parser = parse_hex32)]
    pub wallet_key: Option<[u8; 32]>,

    /// L1 JSON-RPC endpoint the chain posts its DA batches to (the
    /// `DaInbox` settlement contract lives here). Optional: only the
    /// data-availability scenario (S045) needs it; when omitted that
    /// scenario is skipped, so chains that don't expose their L1 to the
    /// suite (or older consumers) run the rest unaffected.
    #[arg(long)]
    pub l1_rpc_url: Option<String>,

    /// Address of the deployed `DaInbox` on `--l1-rpc-url`. Required
    /// together with `--l1-rpc-url` to enable the DA scenario (S045);
    /// the harness that brings up the devnet deploys the inbox and
    /// passes its address here.
    #[arg(long, value_parser = parse_address)]
    pub da_inbox: Option<alloy::primitives::Address>,

    /// Print one row per compiled-in scenario (id + description) on
    /// stdout, then exit 0 without touching the chain. Combine with
    /// `--only` / `--skip` to preview which scenarios a given filter
    /// would actually run. The key parameters (`--admin-key`,
    /// `--sra-key`) are NOT required when this flag is set.
    #[arg(long)]
    pub list: bool,

    /// Filter scenarios by id substring. Accepts comma-separated list.
    /// e.g. `--only S001,S009`. Empty = run all.
    #[arg(long)]
    pub only: Option<String>,

    /// Skip scenarios by id substring. Comma-separated.
    #[arg(long)]
    pub skip: Option<String>,

    /// Report format on stdout.
    #[arg(long, value_enum, default_value_t = ReportFormat::Markdown)]
    pub report: ReportFormat,

    /// Additionally write the report as JSON to this path.
    #[arg(long)]
    pub json_output: Option<PathBuf>,

    /// Additionally write the report as a JUnit XML file. Consumed by
    /// `dorny/test-reporter` and similar CI dashboards so each
    /// scenario shows up as its own pass/fail check on the PR.
    #[arg(long)]
    pub junit_output: Option<PathBuf>,

    /// Verbosity. `-v` info, `-vv` debug, `-vvv` trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// Parse an EVM address (`0x`-prefixed 20-byte hex) for clap.
///
/// Thin wrapper over alloy's `Address` parser so `--da-inbox` carries a
/// typed `Address` rather than a stringly-typed field; the error message
/// is CLI-end-user readable.
pub fn parse_address(input: &str) -> Result<alloy::primitives::Address, String> {
    input.trim().parse().map_err(|e| format!("invalid address: {e}"))
}

/// Parse a 32-byte secp256k1 secret key from hex.
///
/// Accepts either a bare 64-hex-digit string or one with an optional
/// `0x` / `0X` prefix. Returns a typed `[u8; 32]` so the surface in
/// `Cli` stays free of stringly-typed key fields — every downstream
/// constructor takes the same shape.
///
/// Errors are surfaced as `String` rather than a typed enum because
/// that's the signature clap's `value_parser` expects; the error
/// messages are CLI-end-user readable.
pub fn parse_hex32(input: &str) -> Result<[u8; 32], String> {
    let trimmed = input
        .trim()
        .strip_prefix("0x")
        .or_else(|| input.trim().strip_prefix("0X"))
        .unwrap_or_else(|| input.trim());
    if trimmed.len() != 64 {
        return Err(format!(
            "expected 64 hex chars (32 bytes) optionally 0x-prefixed; got {} chars",
            trimmed.len()
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|e| format!("invalid hex: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Initialise the global tracing subscriber from the CLI's `-v`
/// count. Idempotent — safe to call from anywhere in the binary.
///
/// - `0` → `warn` (quiet by default; the markdown report is the
///   user-visible output).
/// - `1` → `info`.
/// - `2` → `debug`.
/// - `>=3` → `trace`.
///
/// All tracing output is written to **stderr** so it never collides
/// with the markdown / JSON report on stdout — without this, a `-vv`
/// CI run hits the 1 MiB `$GITHUB_STEP_SUMMARY` ceiling because tee
/// captures debug events mixed into the report file.
pub fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex32_accepts_prefixed_and_bare() {
        let bare = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let prefixed = format!("0x{bare}");
        assert_eq!(parse_hex32(bare).unwrap(), parse_hex32(&prefixed).unwrap());
    }

    #[test]
    fn parse_hex32_rejects_short_input() {
        assert!(parse_hex32("0xdeadbeef").is_err());
    }

    #[test]
    fn parse_hex32_rejects_non_hex() {
        assert!(
            parse_hex32("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
                .is_err()
        );
    }
}
