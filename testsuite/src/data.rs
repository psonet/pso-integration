//! Data generators for scenario inputs.
//!
//! Scenarios pull a [`SuTemplate`] from [`random_su_args`] and feed its
//! fields straight into `AttesterClient::mint_spending_unit`, etc. The shapes
//! mirror plausible protocol values (EUR, a recent past worldwide-day,
//! a handful of SR/AR fingerprints) without going through any heavy
//! reference generator.
//!
//! The helpers here do NOT touch the chain — they're pure shape
//! generators. Anything that needs a round-trip to L2 lives on the
//! client or the bridge.

use alloy_primitives::U256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::UniformRand;
use chrono::{Datelike, NaiveDate};
use iso_currency::Currency;
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;

/// Random `uint256` id (used for SR / AR / SU / TD ids on chain).
///
/// We sample a fresh 32-byte BE blob so collision probability is
/// negligible across an entire test session — the SR / SU SBTs
/// would revert with `AlreadyExists` on duplicates.
///
/// **Reduced into the BN254 scalar field.** These ids are folded as
/// canonical field elements by the SU/TD-hash precompiles (`0x0211`/
/// `0x0212`), which reject any value `>=` the modulus (a raw 256-bit
/// sample exceeds it ~80% of the time). The field is ~2^254, so the
/// reduction keeps collisions negligible.
pub fn random_id() -> U256 {
    let fr = Fr::rand(&mut OsRng);
    U256::from_be_slice(&fr.into_bigint().to_bytes_be())
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
    /// Worldwide day as compact YYYYMMDD (e.g. 20250923).
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
/// fingerprint-count values (EUR, a recent past day, 1-4 SRs, 0-2 ARs).
pub fn random_su_args() -> SuTemplate {
    let mut rng = OsRng;
    let today = chrono::Utc::now().date_naive();
    // Recent past day: 1-6 days ago.
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

/// Roll a TD-style shape — currency / wwd / amounts (no SR/AR).
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

/// Encode a date as the canonical worldwide-day value: compact YYYYMMDD
/// (e.g. `20250923`), matching the on-chain `worldwideDay` `uint32` slot
/// and the SU/TD hash input. Every date this century fits a `u32`.
fn worldwide_day(date: &NaiveDate) -> u32 {
    date.year() as u32 * 10_000 + date.month() * 100 + date.day()
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
        // Worldwide-day is compact YYYYMMDD; must be a real past date.
        let today = chrono::Utc::now().date_naive();
        let today_yyyymmdd = today.year() as u32 * 10_000 + today.month() * 100 + today.day();
        assert!(
            t.worldwide_day >= 20_210_101,
            "WWD must be >= epoch (2021-01-01)"
        );
        assert!(
            t.worldwide_day <= today_yyyymmdd,
            "WWD must not be in the future"
        );
    }
}
