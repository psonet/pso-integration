//! SRA flow functions.
//!
//! Each function takes an `&L2Client` (with a signer attached) plus
//! the raw call inputs, builds the appropriate transaction, broadcasts
//! it, and waits for the receipt. The SRA CLI is a thin clap-based
//! wrapper around these.

use alloy::primitives::{Address, FixedBytes, TxHash, U256};

use crate::abi::{
    ISpendingRecord, ISpendingRecordAmendment, ISpendingUnit, SPENDING_RECORD,
    SPENDING_RECORD_AMENDMENT, SPENDING_UNIT,
};
use crate::client::L2Client;
use crate::error::L2ClientError;

/// Generic submitter for the SR / SRA contracts — same ABI shape
/// (`submit(uint256 id, string[] keys, bytes32[] values)`), different
/// addresses, so the implementation is shared.
async fn submit_record_like(
    client: &L2Client,
    contract: Address,
    record_id: U256,
    keys: Vec<String>,
    values: Vec<FixedBytes<32>>,
) -> Result<TxHash, L2ClientError> {
    if keys.len() != values.len() {
        return Err(L2ClientError::InvalidInput(format!(
            "keys.len ({}) != values.len ({})",
            keys.len(),
            values.len()
        )));
    }
    let provider = client.write_provider()?;
    // Both interfaces share the same selector & args; pick one for the
    // generated builder.
    let inst = ISpendingRecord::new(contract, provider);
    let pending = inst
        .submit(record_id, keys, values)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .map_err(|e| L2ClientError::Contract(format!("submit: {e}")))?;
    Ok(*pending.tx_hash())
}

/// Submit a spending record. Maps to
/// `SpendingRecord.submit(srId, keys, values)`.
pub async fn register_spending_record(
    client: &L2Client,
    sr_id: U256,
    keys: Vec<String>,
    values: Vec<FixedBytes<32>>,
) -> Result<TxHash, L2ClientError> {
    submit_record_like(client, SPENDING_RECORD, sr_id, keys, values).await
}

/// Submit an amendment record. Maps to
/// `SpendingRecordAmendment.submit(srId, keys, values)`. ABI-identical
/// to `register_spending_record` — different contract address.
pub async fn register_amendment_record(
    client: &L2Client,
    sr_id: U256,
    keys: Vec<String>,
    values: Vec<FixedBytes<32>>,
) -> Result<TxHash, L2ClientError> {
    // ISpendingRecordAmendment shares the same selector / args by
    // design; route through the generic builder.
    let provider = client.write_provider()?;
    let inst = ISpendingRecordAmendment::new(SPENDING_RECORD_AMENDMENT, provider);
    let pending = inst
        .submit(sr_id, keys, values)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .map_err(|e| L2ClientError::Contract(format!("amendment submit: {e}")))?;
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
    pub settlement_currency: u16,
    /// Worldwide-day count (days since 2021-01-01) — `uint32` slot.
    pub worldwide_day: u32,
    /// Settlement amount integer part.
    pub settlement_amount_base: u64,
    /// Settlement amount fractional part (atto).
    pub settlement_amount_atto: u128,
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
            args.settlement_currency,
            args.worldwide_day,
            args.settlement_amount_base,
            args.settlement_amount_atto,
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
