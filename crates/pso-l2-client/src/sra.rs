//! SRA flow functions.
//!
//! Each function takes an `&L2Client` (with a signer attached) plus
//! the raw call inputs, builds the appropriate transaction, broadcasts
//! it, and waits for the receipt. The SRA CLI is a thin clap-based
//! wrapper around these.

use alloy::primitives::{Address, FixedBytes, TxHash, U256};

use crate::abi::{
    IAmendmentRecord, ISpendingRecord, ISpendingUnit, AMENDMENT_RECORD, SPENDING_RECORD,
    SPENDING_UNIT,
};
use crate::client::L2Client;
use crate::error::L2ClientError;

/// Submit a spending record. Maps to `SpendingRecord.submit(srId)`.
///
/// Under the privacy-preserving L2 model SR is a soulbound NFT whose
/// only on-chain state is `ownerOf(srId) == submitting SRA`; the
/// free-form `keys`/`values` metadata of the legacy interface was
/// dropped (it leaked correlatable plaintext and nothing consumed it).
pub async fn register_spending_record(
    client: &L2Client,
    sr_id: U256,
) -> Result<TxHash, L2ClientError> {
    let provider = client.write_provider()?;
    let inst = ISpendingRecord::new(SPENDING_RECORD, provider);
    let pending = inst
        .submit(sr_id)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .map_err(|e| L2ClientError::Contract(format!("SR submit: {e}")))?;
    Ok(*pending.tx_hash())
}

/// Submit an amendment record. Maps to `AmendmentRecord.submit(arId)`.
/// Same soulbound shape as [`register_spending_record`] — different
/// contract address.
pub async fn register_amendment_record(
    client: &L2Client,
    ar_id: U256,
) -> Result<TxHash, L2ClientError> {
    let provider = client.write_provider()?;
    let inst = IAmendmentRecord::new(AMENDMENT_RECORD, provider);
    let pending = inst
        .submit(ar_id)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .map_err(|e| L2ClientError::Contract(format!("AR submit: {e}")))?;
    Ok(*pending.tx_hash())
}

/// All fields for `SpendingUnit.submit`. Bundled into a struct so the
/// CLI's 8 args don't degrade into positional spaghetti.
#[derive(Debug, Clone)]
pub struct MintSpendingUnitArgs {
    /// SU id (uint256). Random — the wallet must store this off-chain
    /// so it can later reference the SU when assembling a TributeDraft.
    pub su_id: U256,
    /// Wallet-supplied Poseidon5 ownership commitment for this SU.
    pub derived_owner: FixedBytes<32>,
    /// ISO 4217 numeric currency code.
    pub currency: u16,
    /// Worldwide-day count (days since 2021-01-01) — `uint32` slot.
    pub worldwide_day: u32,
    /// Amount integer part.
    pub amount_base: u64,
    /// Amount fractional part (atto). On-chain the SU stores this in a
    /// `uint64` slot (atto < 1e18 always fits); we keep the wider
    /// `u128` here for caller convenience and narrow at submit time.
    pub amount_atto: u128,
    /// Spending record IDs included in this SU.
    pub sr_ids: Vec<U256>,
    /// Amendment-record IDs.
    pub amendment_sr_ids: Vec<U256>,
}

/// Mint a SpendingUnit. The SRA is the on-chain submitter; the wallet
/// supplied the `derivedOwner` Poseidon commitment off-line so the
/// chain can later verify a ZK ownership proof against it.
pub async fn mint_spending_unit(
    client: &L2Client,
    args: MintSpendingUnitArgs,
) -> Result<TxHash, L2ClientError> {
    let provider = client.write_provider()?;
    let inst = ISpendingUnit::new(SPENDING_UNIT, provider);
    let pending = inst
        .submit(
            args.su_id,
            args.derived_owner,
            // `referrerAddress` — optional referral attribution the
            // wallet may set off-line. The SRA mint flow has no referrer
            // context, so submit the zero address (== "no referrer").
            Address::ZERO,
            args.currency,
            args.worldwide_day,
            args.amount_base,
            // SU stores atto in a `uint64` slot; atto < 1e18 always fits.
            args.amount_atto as u64,
            args.sr_ids,
            args.amendment_sr_ids,
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .map_err(|e| L2ClientError::Contract(format!("SU submit: {e}")))?;
    Ok(*pending.tx_hash())
}
