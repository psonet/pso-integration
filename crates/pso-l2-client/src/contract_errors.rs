//! Typed Solidity custom-error decoder for the PSO L2 contracts.
//!
//! The contracts revert with named custom errors (`error SRANotActive();`
//! etc.); alloy surfaces them as `alloy::contract::Error::TransportError`
//! with the 4-byte selector + ABI-encoded args in the inner JSON-RPC
//! reply's `data` field. This module centralises:
//!
//! 1. Solidity error definitions matching every variant exposed by the
//!    pso-chain contracts under test (`alloy::sol!`-derived
//!    `SolError`s with the right argument types).
//! 2. A flat enum [`PsoContractError`] each scenario asserts against —
//!    `matches!(err, PsoContractError::SRANotActive)` etc.
//! 3. Two entry points the rest of the crate goes through:
//!    [`decode`] from an `alloy::contract::Error`, and
//!    [`decode_from_bytes`] when only the raw revert bytes are
//!    available (the actor RPC path).
//!
//! Anything that doesn't match a known selector falls through to
//! [`PsoContractError::Other`] with the original error text — that's
//! the gate that catches drift between contract definitions and this
//! decoder.

use alloy::primitives::{Address, U256};
use alloy::sol;
use alloy::sol_types::SolError;

use crate::L2ClientError;

// -----------------------------------------------------------------
// Solidity error declarations — one per chain-side `error ...(...)`.
//
// `alloy::sol!` generates a `SolError` impl giving us `SELECTOR` and
// `abi_decode_raw`. We try each in turn in `decode_from_bytes`. The
// argument types must match the contract definitions byte-for-byte;
// mismatches surface as `Other(...)` (the decode call fails) rather
// than a silently-wrong variant.
// -----------------------------------------------------------------

sol! {
    /// `ISRAAware.SRANotActive()` — agents-pool-side guard on every
    /// SR/AR/SU/TD submit entry point, fires when the EVM-side check
    /// `sraRegistry.isActive(_msgSender())` returns false.
    #[allow(missing_docs)]
    error SRANotActive();

    /// `SoulBoundTokenBase.AlreadyExists()` — `_mint` invoked with an
    /// id whose `submittedBy` slot is already populated.
    #[allow(missing_docs)]
    error AlreadyExists();

    /// `SoulBoundTokenBase.InvalidTokenId()` — `_mint` rejecting `id == 0`.
    #[allow(missing_docs)]
    error InvalidTokenId();

    /// `TributeDraft.EmptyArray()` — `submit(_, _, [], _)` with no SU
    /// ids.
    #[allow(missing_docs)]
    error EmptyArray();

    /// `TributeDraft.NotFound(uint256)` — `getData(suId)` returned a
    /// zero `submittedBy`, i.e. the SU referenced by the TD doesn't
    /// exist.
    #[allow(missing_docs)]
    error NotFound(uint256 spendingUnitIds);

    /// `TributeDraft.MalformedAggregationProof()` — proof body too
    /// short or `numInputs != tier_k`.
    #[allow(missing_docs)]
    error MalformedAggregationProof();

    /// `TributeDraft.InvalidAggregationProof()` — `zk_verify`
    /// precompile rejected the proof, or the public-input prefix did
    /// not match the on-chain reconstruction.
    #[allow(missing_docs)]
    error InvalidAggregationProof();

    /// `TributeDraft.NotSameWorldwideDay()` — SUs in a single TD
    /// straddle two worldwide-day buckets.
    #[allow(missing_docs)]
    error NotSameWorldwideDay();

    /// `TributeDraft.NotSameCurrency()` — SUs in a
    /// single TD use different currencies.
    #[allow(missing_docs)]
    error NotSameCurrency();

    /// `TributeDraft.AggregationTierUnavailable(uint256)` — no
    /// flat-aggregation tier covers `n_su` (must be 1..=64).
    #[allow(missing_docs)]
    error AggregationTierUnavailable(uint256 suCount);

    /// `SpendingUnit.InvalidSpendingRecords(uint256[], uint256[],
    /// uint256[], uint256[])` — consolidated revert for SR / AR
    /// fingerprint validation. Fields are
    /// `(badOwnerSRs, badOwnerARs, duplicateSRs, duplicateARs)`:
    /// the first two list fingerprints whose `submittedBy` is not
    /// `_msgSender()` (or that don't exist); the last two list
    /// fingerprints already consumed by a prior SU mint or repeated
    /// within the same batch.
    #[allow(missing_docs)]
    error InvalidSpendingRecords(
        uint256[] badOwnerSRs,
        uint256[] badOwnerARs,
        uint256[] duplicateSRs,
        uint256[] duplicateARs,
    );

    /// `SpendingUnit.NoSpendingRecords()` — `submit` called with both
    /// SR and AR arrays empty.
    #[allow(missing_docs)]
    error NoSpendingRecords();

    /// `SpendingUnit.TooManySpendingRecords()` — either array exceeds
    /// `MAX_BATCH_SIZE`.
    #[allow(missing_docs)]
    error TooManySpendingRecords();

    /// `SpendingUnit.InvalidAmount()` — amount_atto >= 1e18
    /// or base + atto sum overflows the bounded range.
    #[allow(missing_docs)]
    error InvalidAmount();

    /// `SpendingUnit.SpendingRecordAlreadyExists()` — single-shot
    /// duplicate guard (distinct from the array variant above).
    #[allow(missing_docs)]
    error SpendingRecordAlreadyExists();

    /// `SpendingRecord.InvalidMetadata(string)` / same on
    /// `SpendingRecordAmendment`.
    #[allow(missing_docs)]
    error InvalidMetadata(string reason);

    /// `SRARegistry.NotAdmin()`.
    #[allow(missing_docs)]
    error NotAdmin();

    /// `SRARegistry.AlreadyRegistered(address)`.
    #[allow(missing_docs)]
    error AlreadyRegistered(address sra);

    /// `SRARegistry.NotRegistered(address)`.
    #[allow(missing_docs)]
    error NotRegistered(address sra);

    /// `SRARegistry.ZeroAddress()`.
    #[allow(missing_docs)]
    error ZeroAddress();

    /// `SRARegistry.InvalidMask()` — bad permission bitmask.
    #[allow(missing_docs)]
    error InvalidMask();
}

/// Flat, scenario-facing classification of every revert / pool
/// rejection the suite cares about.
#[derive(Debug, Clone)]
pub enum PsoContractError {
    /// `ISRAAware.SRANotActive`.
    SRANotActive,
    /// `SoulBoundTokenBase.AlreadyExists`.
    AlreadyExists,
    /// `SoulBoundTokenBase.InvalidTokenId`.
    InvalidTokenId,
    /// `TributeDraft.EmptyArray`.
    EmptyArray,
    /// `TributeDraft.NotFound(uint256)`.
    NotFound(U256),
    /// `TributeDraft.MalformedAggregationProof`.
    MalformedAggregationProof,
    /// `TributeDraft.InvalidAggregationProof`.
    InvalidAggregationProof,
    /// `TributeDraft.NotSameWorldwideDay`.
    NotSameWorldwideDay,
    /// `TributeDraft.NotSameCurrency`.
    NotSameCurrency,
    /// `TributeDraft.AggregationTierUnavailable(uint256)`. Truncated
    /// to `u32` because every valid tier fits there.
    AggregationTierUnavailable(u32),
    /// `SpendingUnit.InvalidSpendingRecords(...)` — consolidated SR/AR
    /// validation revert. Fields, in order, are:
    /// `(bad_owner_srs, bad_owner_ars, duplicate_srs, duplicate_ars)`.
    /// A fingerprint never lands in both the bad-owner and duplicate
    /// arms — bad-owner takes priority on the contract side.
    InvalidSpendingRecords(Vec<U256>, Vec<U256>, Vec<U256>, Vec<U256>),
    /// `SpendingUnit.NoSpendingRecords` — empty SR and AR arrays.
    NoSpendingRecords,
    /// `SpendingUnit.TooManySpendingRecords` — batch exceeds
    /// `MAX_BATCH_SIZE`.
    TooManySpendingRecords,
    /// `SpendingUnit.InvalidAmount`.
    InvalidAmount,
    /// `SpendingUnit.SpendingRecordAlreadyExists` (single-shot variant).
    SpendingRecordAlreadyExists,
    /// `SpendingRecord{,Amendment}.InvalidMetadata(string)`.
    InvalidMetadata(String),
    /// `SRARegistry.NotAdmin`.
    NotAdmin,
    /// `SRARegistry.AlreadyRegistered(address)`.
    AlreadyRegistered(Address),
    /// `SRARegistry.NotRegistered(address)`.
    NotRegistered(Address),
    /// `SRARegistry.ZeroAddress`.
    ZeroAddress,
    /// `SRARegistry.InvalidMask`.
    InvalidMask,
    /// Agents-pool / actor-pool rejection: the wallet's tx was never
    /// admitted. Carries the structured reason string the validator
    /// printed (`MethodNotPermitted { to, selector }`, `BadVdfInputBinding`,
    /// `Malformed(...)`, etc.). Matched on substring in
    /// [`PsoContractError::is_method_not_permitted`] and friends.
    PoolRejection(String),
    /// `MethodNotPermitted { to, selector }` extracted from a
    /// `PoolRejection`. Cheaper to match against than a substring.
    MethodNotPermitted(Address, [u8; 4]),
    /// Anything else — keep the original message for the test
    /// assertion failure path.
    Other(String),
}

impl PsoContractError {
    /// Convenience predicate: did the chain refuse the tx with any
    /// `MethodNotPermitted` flavour (typed variant OR pool-rejection
    /// string)?
    pub fn is_method_not_permitted(&self) -> bool {
        match self {
            PsoContractError::MethodNotPermitted(_, _) => true,
            PsoContractError::PoolRejection(s) => s.contains("MethodNotPermitted"),
            _ => false,
        }
    }
}

impl std::fmt::Display for PsoContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PsoContractError::SRANotActive => write!(f, "SRANotActive"),
            PsoContractError::AlreadyExists => write!(f, "AlreadyExists"),
            PsoContractError::InvalidTokenId => write!(f, "InvalidTokenId"),
            PsoContractError::EmptyArray => write!(f, "EmptyArray"),
            PsoContractError::NotFound(id) => write!(f, "NotFound({id})"),
            PsoContractError::MalformedAggregationProof => write!(f, "MalformedAggregationProof"),
            PsoContractError::InvalidAggregationProof => write!(f, "InvalidAggregationProof"),
            PsoContractError::NotSameWorldwideDay => write!(f, "NotSameWorldwideDay"),
            PsoContractError::NotSameCurrency => {
                write!(f, "NotSameCurrency")
            }
            PsoContractError::AggregationTierUnavailable(n) => {
                write!(f, "AggregationTierUnavailable({n})")
            }
            PsoContractError::InvalidSpendingRecords(bad_sr, bad_ar, dup_sr, dup_ar) => {
                write!(
                    f,
                    "InvalidSpendingRecords(bad_sr={bad_sr:?}, bad_ar={bad_ar:?}, dup_sr={dup_sr:?}, dup_ar={dup_ar:?})"
                )
            }
            PsoContractError::NoSpendingRecords => write!(f, "NoSpendingRecords"),
            PsoContractError::TooManySpendingRecords => write!(f, "TooManySpendingRecords"),
            PsoContractError::InvalidAmount => write!(f, "InvalidAmount"),
            PsoContractError::SpendingRecordAlreadyExists => {
                write!(f, "SpendingRecordAlreadyExists")
            }
            PsoContractError::InvalidMetadata(r) => write!(f, "InvalidMetadata({r:?})"),
            PsoContractError::NotAdmin => write!(f, "NotAdmin"),
            PsoContractError::AlreadyRegistered(a) => write!(f, "AlreadyRegistered({a})"),
            PsoContractError::NotRegistered(a) => write!(f, "NotRegistered({a})"),
            PsoContractError::ZeroAddress => write!(f, "ZeroAddress"),
            PsoContractError::InvalidMask => write!(f, "InvalidMask"),
            PsoContractError::PoolRejection(s) => write!(f, "PoolRejection({s})"),
            PsoContractError::MethodNotPermitted(to, sel) => {
                write!(
                    f,
                    "MethodNotPermitted(to={to:#x}, selector=0x{})",
                    hex::encode(sel)
                )
            }
            PsoContractError::Other(s) => write!(f, "Other({s})"),
        }
    }
}

impl std::error::Error for PsoContractError {}

// -----------------------------------------------------------------
// Decoders
// -----------------------------------------------------------------

/// Try to extract revert-data bytes from an `alloy::contract::Error`
/// and decode them. Falls back to the textual error if no `data` is
/// present.
pub fn decode(err: alloy::contract::Error) -> PsoContractError {
    decode_text(&err.to_string())
}

/// Convert an `L2ClientError` (the top-level pso-l2-client error
/// wrapping alloy + everything else) into a typed
/// [`PsoContractError`]. The common path is
/// `L2ClientError::Contract(String)` — alloy's Display output
/// carries the hex-encoded revert data plus any framing the JSON-RPC
/// layer added. Everything else collapses into
/// [`PsoContractError::Other`].
///
/// Typical scenario / client-side usage:
///
/// ```ignore
/// let err = sra.call().await.map_err(into_pso_error)?;
/// match err {
///     PsoContractError::SRANotActive => { ... }
///     PsoContractError::NotFound(id) => { ... }
///     other => Err(other),
/// }
/// ```
pub fn into_pso_error(err: L2ClientError) -> PsoContractError {
    match err {
        L2ClientError::Contract(s) => decode_text(&s),
        other => PsoContractError::Other(other.to_string()),
    }
}

/// Same decoder, starting from the textual error rendition. Useful
/// when the error has already been collapsed into a `String` by an
/// upstream wrapper (e.g. `L2ClientError::Contract(String)`).
pub fn decode_text(msg: &str) -> PsoContractError {
    // First: did the inner JSON-RPC error carry hex `data`? alloy
    // surfaces it inline in the Display impl as `data: "0x..."`. We
    // can also try `as_revert_data()` on `alloy::contract::Error`
    // when available, but the textual path is uniform across the
    // alloy versions in this workspace.
    if let Some(bytes) = extract_revert_bytes(msg) {
        return decode_from_bytes(&bytes);
    }

    // Pool-level rejection? The agents-pool wraps `RejectionReason`
    // in a `PsoPoolError` whose Display is `"PSO pool rejection: ..."`.
    // The actor RPC surfaces "method not permitted" / VDF rejections
    // as `-32602` with the message body in the textual error.
    if msg.contains("PSO pool rejection")
        || msg.contains("MethodNotPermitted")
        || msg.contains("BadVdfInputBinding")
        || msg.contains("magic-prefixed")
    {
        if let Some(parsed) = parse_method_not_permitted(msg) {
            return parsed;
        }
        return PsoContractError::PoolRejection(msg.to_string());
    }

    PsoContractError::Other(msg.to_string())
}

/// Try every known selector. Returns `Other(...)` (with a short
/// debug-friendly text) when none matches.
pub fn decode_from_bytes(data: &[u8]) -> PsoContractError {
    if data.len() < 4 {
        return PsoContractError::Other(format!("revert data too short ({} bytes)", data.len()));
    }
    let selector: [u8; 4] = data[..4].try_into().expect("len >= 4");
    let body = &data[4..];

    // Static (no-arg) errors — selector match alone is sufficient.
    if selector == SRANotActive::SELECTOR {
        return PsoContractError::SRANotActive;
    }
    if selector == AlreadyExists::SELECTOR {
        return PsoContractError::AlreadyExists;
    }
    if selector == InvalidTokenId::SELECTOR {
        return PsoContractError::InvalidTokenId;
    }
    if selector == EmptyArray::SELECTOR {
        return PsoContractError::EmptyArray;
    }
    if selector == MalformedAggregationProof::SELECTOR {
        return PsoContractError::MalformedAggregationProof;
    }
    if selector == InvalidAggregationProof::SELECTOR {
        return PsoContractError::InvalidAggregationProof;
    }
    if selector == NotSameWorldwideDay::SELECTOR {
        return PsoContractError::NotSameWorldwideDay;
    }
    if selector == NotSameCurrency::SELECTOR {
        return PsoContractError::NotSameCurrency;
    }
    if selector == InvalidAmount::SELECTOR {
        return PsoContractError::InvalidAmount;
    }
    if selector == NoSpendingRecords::SELECTOR {
        return PsoContractError::NoSpendingRecords;
    }
    if selector == TooManySpendingRecords::SELECTOR {
        return PsoContractError::TooManySpendingRecords;
    }
    if selector == SpendingRecordAlreadyExists::SELECTOR {
        return PsoContractError::SpendingRecordAlreadyExists;
    }
    if selector == NotAdmin::SELECTOR {
        return PsoContractError::NotAdmin;
    }
    if selector == ZeroAddress::SELECTOR {
        return PsoContractError::ZeroAddress;
    }
    if selector == InvalidMask::SELECTOR {
        return PsoContractError::InvalidMask;
    }

    // Parameterised errors — decode the body. A decode failure means
    // the chain's interface drifted from our `sol!` block; fall
    // through to `Other` so the test failure mentions the raw bytes.
    if selector == NotFound::SELECTOR {
        if let Ok(NotFound { spendingUnitIds }) = NotFound::abi_decode_raw(body) {
            return PsoContractError::NotFound(spendingUnitIds);
        }
    }
    if selector == AggregationTierUnavailable::SELECTOR {
        if let Ok(AggregationTierUnavailable { suCount }) =
            AggregationTierUnavailable::abi_decode_raw(body)
        {
            return PsoContractError::AggregationTierUnavailable(
                suCount.try_into().unwrap_or(u32::MAX),
            );
        }
    }
    if selector == InvalidSpendingRecords::SELECTOR {
        if let Ok(InvalidSpendingRecords {
            badOwnerSRs,
            badOwnerARs,
            duplicateSRs,
            duplicateARs,
        }) = InvalidSpendingRecords::abi_decode_raw(body)
        {
            return PsoContractError::InvalidSpendingRecords(
                badOwnerSRs,
                badOwnerARs,
                duplicateSRs,
                duplicateARs,
            );
        }
    }
    if selector == InvalidMetadata::SELECTOR {
        if let Ok(InvalidMetadata { reason }) = InvalidMetadata::abi_decode_raw(body) {
            return PsoContractError::InvalidMetadata(reason);
        }
    }
    if selector == AlreadyRegistered::SELECTOR {
        if let Ok(AlreadyRegistered { sra }) = AlreadyRegistered::abi_decode_raw(body) {
            return PsoContractError::AlreadyRegistered(sra);
        }
    }
    if selector == NotRegistered::SELECTOR {
        if let Ok(NotRegistered { sra }) = NotRegistered::abi_decode_raw(body) {
            return PsoContractError::NotRegistered(sra);
        }
    }

    PsoContractError::Other(format!(
        "unknown selector 0x{} (body {} bytes): {}",
        hex::encode(selector),
        body.len(),
        hex::encode(data)
    ))
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

/// Pull a hex `0x...` blob out of the alloy error's Display output.
/// alloy formats it as `data: "0x..."`; we look for either that key
/// or a bare `0x[0-9a-f]+` sequence at least 8 hex digits long (i.e.
/// at least one selector worth of data).
fn extract_revert_bytes(msg: &str) -> Option<Vec<u8>> {
    // Prefer the explicit `data: "..."` form.
    if let Some(idx) = msg.find("data: \"0x") {
        let rest = &msg[idx + "data: \"".len() + 2..]; // skip past `0x`
        if let Some(end) = rest.find('"') {
            return hex::decode(&rest[..end]).ok();
        }
    }
    // Bare `0x...` fallback. Skip until we find one that's at least
    // 8 hex chars long.
    let lower = msg.to_lowercase();
    let mut search = lower.as_str();
    while let Some(idx) = search.find("0x") {
        let rest = &search[idx + 2..];
        let end = rest
            .char_indices()
            .find(|(_, c)| !c.is_ascii_hexdigit())
            .map(|(i, _)| i)
            .unwrap_or(rest.len());
        if end >= 8 {
            if let Ok(bytes) = hex::decode(&rest[..end]) {
                return Some(bytes);
            }
        }
        search = &rest[end..];
    }
    None
}

/// Parse a `MethodNotPermitted { to: 0x..., selector: [0x..] }` debug
/// dump out of a pool rejection message. Returns `None` when the
/// pattern doesn't match — the caller falls back to
/// `PoolRejection(msg)` then.
fn parse_method_not_permitted(msg: &str) -> Option<PsoContractError> {
    // Pattern (as printed by `RejectionReason`'s derived Debug):
    //   "MethodNotPermitted { to: 0x5200…0007, selector: [0xa9, 0x05…] }"
    // We're not strict — anything matching the basic shape works.
    let i = msg.find("MethodNotPermitted")?;
    let tail = &msg[i..];
    let to = parse_addr_after(tail, "to:")?;
    let sel = parse_selector_after(tail, "selector:")?;
    Some(PsoContractError::MethodNotPermitted(to, sel))
}

fn parse_addr_after(s: &str, key: &str) -> Option<Address> {
    let i = s.find(key)?;
    let rest = &s[i + key.len()..];
    let lower = rest.to_lowercase();
    let start = lower.find("0x")? + 2;
    let take = lower[start..]
        .char_indices()
        .find(|(_, c)| !c.is_ascii_hexdigit())
        .map(|(j, _)| j)
        .unwrap_or(lower.len() - start);
    let hex_s = &lower[start..start + take];
    let bytes = hex::decode(hex_s).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Some(Address::from(addr))
}

fn parse_selector_after(s: &str, key: &str) -> Option<[u8; 4]> {
    // Debug prints arrays as `[1, 2, 3, 4]` (decimal) for u8 by
    // default. We accept both decimal-array and hex-byte forms.
    let i = s.find(key)?;
    let rest = &s[i + key.len()..];
    let open = rest.find('[')?;
    let close = rest[open..].find(']')?;
    let inner = &rest[open + 1..open + close];
    let mut out = [0u8; 4];
    let mut idx = 0;
    for tok in inner.split(',') {
        if idx >= 4 {
            return None;
        }
        let t = tok.trim().trim_start_matches("0x");
        let v = if let Ok(b) = u8::from_str_radix(t, 16) {
            b
        } else {
            t.parse::<u8>().ok()?
        };
        out[idx] = v;
        idx += 1;
    }
    if idx == 4 {
        Some(out)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_sra_not_active_selector() {
        let bytes = SRANotActive::SELECTOR.to_vec();
        match decode_from_bytes(&bytes) {
            PsoContractError::SRANotActive => {}
            other => panic!("expected SRANotActive, got {other}"),
        }
    }

    #[test]
    fn decode_already_exists_selector() {
        match decode_from_bytes(&AlreadyExists::SELECTOR) {
            PsoContractError::AlreadyExists => {}
            other => panic!("expected AlreadyExists, got {other}"),
        }
    }

    #[test]
    fn decode_invalid_token_id_selector() {
        match decode_from_bytes(&InvalidTokenId::SELECTOR) {
            PsoContractError::InvalidTokenId => {}
            other => panic!("expected InvalidTokenId, got {other}"),
        }
    }

    #[test]
    fn decode_unknown_selector_is_other() {
        match decode_from_bytes(&[0xde, 0xad, 0xbe, 0xef]) {
            PsoContractError::Other(_) => {}
            other => panic!("expected Other, got {other}"),
        }
    }

    #[test]
    fn extract_data_field_from_message() {
        let msg = r#"server returned an error response: data: "0x82b42900""#;
        let bytes = extract_revert_bytes(msg).expect("hex extracted");
        assert_eq!(bytes, vec![0x82, 0xb4, 0x29, 0x00]);
    }
}
