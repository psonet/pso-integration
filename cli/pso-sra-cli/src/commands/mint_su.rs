//! `pso-sra-cli mint-su` — mint a SpendingUnit on L2.
//!
//! SU issuance goes through the attester FFI: `generate_nft_header`
//! (consent box over the wallet's `consent_pk`) + `issue_with_header`
//! (fold in the body + record fingerprints) produce the SU id /
//! `derivedOwner` / `nft_hash`. The CLI then submits the FFI-computed
//! SpendingUnit on-chain.

use clap::Args as ClapArgs;
use eyre::Result;

use crate::client::SraRpc;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Wallet's consent public key — a 32-byte compressed PsoV1 point
    /// (`0x...`). The attester derives `derivedOwner` from it.
    #[arg(long)]
    pub consent_pk: String,
    /// Per-issuance entropy seed (`0x...`, >= 32 bytes). Vary it per
    /// issuance — the attester holds no RNG state, so the same seed
    /// yields the same SU id / owner.
    #[arg(long)]
    pub seed: String,
    /// Wallet self-address from consent init (20-byte hex `0x...`).
    /// Stamped on the SU as `referrerAddress`. Defaults to the zero
    /// address (no referrer).
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000")]
    pub referrer: String,
    /// ISO 4217 currency numeric code (e.g. 978 = EUR).
    #[arg(long)]
    pub currency: u16,
    /// Worldwide-day count (compact YYYYMMDD).
    #[arg(long)]
    pub worldwide_day: u32,
    /// Amount integer part.
    #[arg(long)]
    pub amount_base: u64,
    /// Amount fractional part (atto, uint64; atto < 1e18).
    #[arg(long, default_value_t = 0)]
    pub amount_atto: u64,
    /// Comma-separated SR ids backing this SU (hex `0x...`, canonical
    /// 32-byte field elements).
    #[arg(long)]
    pub sr_ids: String,
    /// Comma-separated amendment-SR ids (hex `0x...`). Optional.
    #[arg(long, default_value = "")]
    pub amendment_sr_ids: String,
}

pub async fn run(client: &SraRpc, args: Args) -> Result<()> {
    let consent_pk = super::strip_hex(&args.consent_pk)?;
    let seed = super::strip_hex(&args.seed)?;
    let referrer = super::parse_address(&args.referrer)?;
    let sr_ids = super::parse_uint256_list(&args.sr_ids)?;
    let ar_ids = super::parse_uint256_list(&args.amendment_sr_ids)?;

    // Record fingerprints are the same canonical BE bytes the on-chain
    // SU stores; the attester folds them into `nft_hash`.
    let sr_fps: Vec<Vec<u8>> = sr_ids.iter().map(|id| id.to_be_bytes::<32>().to_vec()).collect();
    let ar_fps: Vec<Vec<u8>> = ar_ids.iter().map(|id| id.to_be_bytes::<32>().to_vec()).collect();

    // Attester FFI: consent-box header + full issuance, bound to the
    // SRA's on-chain address.
    let attester = pso_attester_integration::Attester::new(client.address().to_vec())
        .map_err(|e| eyre::eyre!("attester: {e:?}"))?;
    let header = attester
        .generate_nft_header(seed, consent_pk)
        .map_err(|e| eyre::eyre!("generate_nft_header: {e:?}"))?;
    let issued = attester
        .issue_with_header(
            header,
            args.worldwide_day,
            args.currency,
            args.amount_base,
            args.amount_atto,
            referrer.to_vec(),
            sr_fps,
            ar_fps,
        )
        .map_err(|e| eyre::eyre!("issue_with_header: {e:?}"))?;

    let su_id = alloy_primitives::U256::from_be_slice(&issued.spending_unit.su_id);
    let derived_owner =
        alloy_primitives::FixedBytes::<32>::from_slice(&issued.spending_unit.derived_owner);

    let tx_hash = client
        .mint_spending_unit(
            su_id,
            derived_owner,
            referrer,
            args.currency,
            args.worldwide_day,
            args.amount_base,
            args.amount_atto,
            sr_ids,
            ar_ids,
        )
        .await?;
    println!(
        "{{\"tx_hash\":\"{tx_hash:?}\",\"su_id\":\"{su_id:#x}\",\"derived_owner\":\"0x{}\"}}",
        hex::encode(issued.spending_unit.derived_owner)
    );
    Ok(())
}
