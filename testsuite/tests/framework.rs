//! Pure-Rust unit tests for the testsuite framework.
//!
//! These do NOT require a running L2 node — they exercise envelope
//! encoding, the typed error decoder, the data generators, and the
//! CLI hex parser. `cargo test -p pso-e2e-testsuite --lib` (which
//! also runs in-crate `#[cfg(test)]` modules) plus
//! `cargo test -p pso-e2e-testsuite --test framework` keeps dev
//! coverage useful when no devnet is up.
//!
//! The scenario surface itself is network-bound by design; that's
//! what the `pso-e2e` binary is for.

use pso_e2e_testsuite::cli::parse_hex32;
use pso_e2e_testsuite::clients::envelope::{
    build_users_pool_calldata, derive_vdf_input, pso_magic, DEFAULT_PSO_MAGIC, PSO_MIN_HEADER,
};
use pso_e2e_testsuite::data::{currency_eur, random_id, random_sr_metadata, random_su_args};
use pso_l2_client::contract_errors::{decode_from_bytes, decode_text};
use pso_l2_client::PsoContractError;

/// Sanity-check the envelope header layout: 4B magic + 32B nullifier
/// + 32B vdf_input + 48B vdf_output + 48B vdf_proof + 8B
/// submitted_block = 172B, followed by `inner` verbatim.
#[test]
fn envelope_header_layout() {
    let signer = alloy::primitives::Address::from([0xab; 20]);
    let inner = vec![0u8; 96];
    let env = build_users_pool_calldata(signer, 0, 1, 19_280_501, 16, &inner).unwrap();
    assert_eq!(env.len(), PSO_MIN_HEADER + inner.len());
    assert_eq!(&env[..4], &pso_magic());
    assert_eq!(&env[PSO_MIN_HEADER..], &inner[..]);
}

/// Confirm the VDF binding is deterministic on identical inputs and
/// changes on any input change. Drift here would break the chain's
/// re-derivation step and surface as `BadVdfInputBinding`.
#[test]
fn vdf_input_binding_is_canonical() {
    let signer = alloy::primitives::Address::from([0xcd; 20]);
    let a = derive_vdf_input(signer, 7, 100, 19_280_501);
    let b = derive_vdf_input(signer, 7, 100, 19_280_501);
    let c = derive_vdf_input(signer, 8, 100, 19_280_501);
    assert_eq!(a, b, "deterministic on equal inputs");
    assert_ne!(a, c, "differs on nonce change");
}

/// `DEFAULT_PSO_MAGIC` must match the chain's
/// `pso-chain/crates/pso-chain/src/pool/calldata.rs::DEFAULT_PSO_MAGIC`.
/// If this changes, both sides have to update in lockstep — pin it
/// in a test so the drift is loud.
#[test]
fn pso_magic_default_pinned() {
    assert_eq!(DEFAULT_PSO_MAGIC, [0xCA, 0xFE, 0xD0, 0x0D]);
}

/// Typed-error decoder round trip for a no-arg selector.
#[test]
fn errors_decode_sra_not_active() {
    use alloy::sol_types::SolError;
    alloy::sol! {
        error SRANotActive();
    }
    match decode_from_bytes(&SRANotActive::SELECTOR) {
        PsoContractError::SRANotActive => {}
        other => panic!("expected SRANotActive, got {other}"),
    }
}

/// Pool rejection round-trip through the textual decoder.
#[test]
fn errors_decode_pool_rejection_text() {
    let msg = "PSO pool rejection: MagicMismatch";
    let typed = decode_text(msg);
    assert!(matches!(typed, PsoContractError::PoolRejection(_)));
}

/// `random_su_args` should produce shapes compatible with the on-chain
/// contract (at least 1 SR per SU; wwd within u32 bounds).
#[test]
fn data_random_su_args_shape() {
    let t = random_su_args();
    assert!(t.currency != 0);
    assert!(t.sr_count >= 1);
    let _ = currency_eur(); // surfaces the helper for future tests
}

/// `random_sr_metadata` should always carry at least one key/value
/// pair so `SR.submit` never short-circuits on length checks.
#[test]
fn data_random_sr_metadata_nonempty() {
    let v = random_sr_metadata();
    assert!(!v.is_empty());
    assert!(v.iter().all(|(k, _)| !k.is_empty()));
}

/// `random_id` should produce non-zero ids across reasonable
/// reruns. The chance of OsRng producing `U256::ZERO` is
/// astronomically small; this catches a rigged generator more than
/// statistical drift.
#[test]
fn data_random_id_nonzero() {
    for _ in 0..32 {
        let id = random_id();
        assert!(!id.is_zero(), "random_id must not roll U256::ZERO");
    }
}

/// `parse_hex32` accepts both `0x`-prefixed and bare 64-char input;
/// rejects anything else.
#[test]
fn cli_parse_hex32_round_trip() {
    let bare = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let prefixed = format!("0x{bare}");
    let a = parse_hex32(bare).unwrap();
    let b = parse_hex32(&prefixed).unwrap();
    assert_eq!(a, b);
    assert!(parse_hex32("0x1234").is_err());
    assert!(parse_hex32("not-hex").is_err());
}

/// JUnit emitter renders a pass + a fail case in the canonical
/// Surefire shape `dorny/test-reporter` consumes:
///
///   <testsuites name="pso-e2e" tests="N" failures="M" time="T">
///     <testsuite ...>
///       <testcase name="..." time="..."/>
///       <testcase ...><failure message="..." type="...">...</failure></testcase>
///     </testsuite>
///   </testsuites>
///
/// The failure message attribute must carry only the first line of the
/// report; the body holds the full eyre-rendered chain. XML entities in
/// either side are escaped.
#[test]
fn report_junit_shape_pass_and_fail() {
    use pso_e2e_testsuite::scenario::{Outcome, Report, ScenarioResult};

    let mut report = Report::new();
    report.push(ScenarioResult {
        id: "S001",
        description: "happy flow",
        duration_ms: 1234,
        outcome: Outcome::Pass,
    });
    report.push(ScenarioResult {
        id: "S002",
        description: "<edge> & \"weird\" chars",
        duration_ms: 5,
        outcome: Outcome::Fail(eyre::eyre!("first line of error\nsecond line")),
    });

    let xml = report.to_junit_xml();
    // Header.
    assert!(xml.starts_with("<?xml version=\"1.0\""));
    assert!(xml.contains("tests=\"2\""));
    assert!(xml.contains("failures=\"1\""));

    // Pass row — self-closing testcase, no <failure> nested.
    assert!(xml.contains("name=\"S001 - happy flow\""));
    assert!(xml.contains("time=\"1.234\""));

    // Fail row — failure message holds first line only.
    assert!(xml.contains("name=\"S002 - &lt;edge&gt; &amp; &quot;weird&quot; chars\""));
    assert!(xml.contains("message=\"first line of error\""));
    assert!(xml.contains("first line of error\nsecond line"));
}
