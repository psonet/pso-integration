//! Data generators for scenario inputs.
//!
//! Backed by `pso_nft::{SpendingUnit, TributeDraft, Generated}` so the
//! shapes match the protocol's reference test data. Scenarios pull
//! a [`SuTemplate`] from [`random_su_args`] and feed its fields
//! straight into `SraClient::mint_spending_unit`, etc.
//!
//! The helpers here do NOT touch the chain — they're pure shape
//! generators. Anything that needs a round-trip to L2 lives on the
//! client or the bridge.

use alloy::primitives::{FixedBytes, U256};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use chrono::{Datelike, NaiveDate};
use iso_currency::Currency;
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;

// pso_nft re-exported so test callers can reach into the protocol's
// reference NFT shapes when they need them (e.g. for `compute_spending_unit_hash`
// inputs in S001). We deliberately do not call `SpendingUnit::generate`
// here — it allocates a `barretenberg-rs`-backed Grumpkin keypair via
// `Owner::generate`, which is a heavy dependency for tests that only
// need plausible currency / amount / wwd values.
#[allow(unused_imports)]
pub use pso_nft::{Generated, SpendingUnit, TributeDraft};

/// Random `uint256` id (used for SR / AR / SU / TD ids on chain).
///
/// We sample a fresh 32-byte BE blob so collision probability is
/// negligible across an entire test session — the SR / SU SBTs
/// would revert with `AlreadyExists` on duplicates.
pub fn random_id() -> U256 {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    U256::from_be_bytes(bytes)
}

/// Random 32-byte secp256k1 secret-key material. Caller must wrap
/// in `k256::SecretKey::from_slice` to reject zero (statistically
/// not going to happen, but the API forces the check).
pub fn random_secret_key() -> [u8; 32] {
    let mut sk = [0u8; 32];
    OsRng.fill_bytes(&mut sk);
    sk
}

/// Shape the scenarios use when constructing a `MintSpendingUnitArgs`.
/// All fields are post-validation: `worldwide_day` fits a `u32`,
/// `currency` is ISO-4217 numeric, etc.
#[derive(Debug, Clone)]
pub struct SuTemplate {
    /// ISO 4217 numeric currency code.
    pub currency: u16,
    /// Worldwide-day count (days since 2021-01-01).
    pub worldwide_day: u32,
    /// Amount integer part.
    pub amount_base: u64,
    /// Amount fractional part (atto). Always 0 in
    /// scenario inputs — the on-chain side handles u128 but
    /// nothing in the suite needs sub-base precision.
    pub amount_atto: u128,
    /// How many SR ids the SU should consume.
    pub sr_count: usize,
    /// How many AR ids the SU should consume.
    pub ar_count: usize,
}

/// Roll a [`SuTemplate`] with plausible currency / amount / wwd /
/// fingerprint-count values. The shape mirrors what
/// `pso_nft::SpendingUnit::generate` produces (EUR, recent past day,
/// 1-4 SRs, 0-2 ARs) without going through the protocol's reference
/// generator — that path constructs a Grumpkin owner via
/// `barretenberg-rs` which we don't need for arg-shape generation.
pub fn random_su_args() -> SuTemplate {
    let mut rng = OsRng;
    let today = chrono::Utc::now().date_naive();
    // Same shape as `pso_nft::SpendingUnit::generate`: 1-6 days ago.
    let days_shift = rng.gen_range(1..7);
    let wwd_date = today - chrono::Duration::days(days_shift as i64);
    SuTemplate {
        currency: Currency::EUR.numeric(),
        worldwide_day: worldwide_day(&wwd_date),
        amount_base: rng.gen_range(10..500),
        amount_atto: 0,
        sr_count: rng.gen_range(1..5),
        ar_count: rng.gen_range(0..3),
    }
}

/// Roll a TD-style shape — currency / wwd / amounts. Same caveat
/// as [`random_su_args`]: this does NOT call into `pso_nft` so we
/// avoid the Grumpkin/barretenberg setup cost.
pub fn random_td_args() -> SuTemplate {
    let mut rng = OsRng;
    let today = chrono::Utc::now().date_naive();
    let days_shift = rng.gen_range(1..7);
    let wwd_date = today - chrono::Duration::days(days_shift as i64);
    SuTemplate {
        currency: Currency::EUR.numeric(),
        worldwide_day: worldwide_day(&wwd_date),
        amount_base: rng.gen_range(250..2000),
        amount_atto: 0,
        sr_count: 0,
        ar_count: 0,
    }
}

/// Random metadata vector for `SpendingRecord.submit(srId, keys, values)`.
/// Keys mirror the production "merchant / amount / ..." shape; values
/// are random `bytes32` blobs.
pub fn random_sr_metadata() -> Vec<(String, FixedBytes<32>)> {
    let mut rng = OsRng;
    let mut keys = vec!["merchant".to_string(), "amount".to_string()];
    if rng.gen_bool(0.5) {
        keys.push("timestamp".to_string());
    }
    keys.into_iter()
        .map(|k| {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            (k, FixedBytes::from(b))
        })
        .collect()
}

/// Same shape as [`random_sr_metadata`] but with amendment-style keys.
pub fn random_ar_metadata() -> Vec<(String, FixedBytes<32>)> {
    let mut rng = OsRng;
    let keys = vec!["correction".to_string(), "reason".to_string()];
    keys.into_iter()
        .map(|k| {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            (k, FixedBytes::from(b))
        })
        .collect()
}

/// Random worldwide-day count compatible with the SU contract's
/// `uint32` slot.
fn worldwide_day(date: &NaiveDate) -> u32 {
    let epoch = NaiveDate::from_ymd_opt(2021, 1, 1).expect("WWD epoch");
    // Saturating cast — every plausible date this century fits u32.
    (*date - epoch).num_days().max(0).min(u32::MAX as i64) as u32
}

/// Reduce a `pso_nft` `Fr` fingerprint into a `U256` SR id. The
/// in-protocol SR fingerprint is a Poseidon hash mod the BN254
/// scalar field; the on-chain SBT slot is a `uint256`. We map LE
/// → BE so the bytes parse identically on the chain side.
#[allow(dead_code)]
pub fn fr_to_u256_be(fr: &Fr) -> U256 {
    let le = fr.into_bigint().to_bytes_le();
    let mut be = [0u8; 32];
    for (i, b) in le.iter().take(32).enumerate() {
        be[31 - i] = *b;
    }
    U256::from_be_bytes(be)
}

/// Iso-currency lookup; surfaced here for scenarios that need to
/// reason about currency types without re-importing the dep.
#[allow(dead_code)]
pub fn currency_eur() -> u16 {
    Currency::EUR.numeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn su_template_within_protocol_bounds() {
        let t = random_su_args();
        assert!(t.currency != 0);
        assert!(t.sr_count >= 1);
        // Days since 2021-01-01; "now" must fit a u32.
        let today = chrono::Utc::now().date_naive();
        let epoch = NaiveDate::from_ymd_opt(2021, 1, 1).unwrap();
        let max = (today - epoch).num_days() as u32;
        assert!(t.worldwide_day <= max, "WWD must be in the past");
    }

    #[test]
    fn metadata_round_trip() {
        let v = random_sr_metadata();
        assert!(!v.is_empty());
        assert!(v.iter().all(|(k, _)| !k.is_empty()));
    }
}

// Keep `Datelike` referenced so future helpers that print the date
// (debug logs etc.) don't need to re-import.
#[allow(dead_code)]
fn _datelike_anchor(d: &NaiveDate) -> i32 {
    d.year()
}
