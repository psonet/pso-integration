//! End-to-end integration test exercising the SRA + Wallet flow
//! programmatically (no CLI invocation — same library functions the
//! CLIs use).
//!
//! ## Prerequisites
//!
//! - A running PSO L2 dev node accessible at `$PSO_L2_RPC` (defaults to
//!   `http://127.0.0.1:19545`).
//! - The predeployed contracts at the genesis addresses
//!   `0x5200…0004..0007` accepting transactions from the admin signer.
//! - Aggregation prover heavy native deps (`noir_rs` + `barretenberg-rs`)
//!   built and linkable.
//!
//! Marked `#[ignore]` so a normal `cargo test` skips them. Opt in via:
//!
//! ```text
//! PSO_L2_RPC=http://127.0.0.1:19545 \
//!     cargo test -p pso-l2-e2e-tests -- --ignored
//! ```
//!
//! ## Flow
//!
//! 1. SRA registers two spending records (`register_spending_record`).
//! 2. SRA registers one amendment record (`register_amendment_record`).
//! 3. For each SU we want to mint, the wallet runs `prepare_su_ownership`
//!    to roll a (nonce, derivedOwner) pair, then SRA calls
//!    `mint_spending_unit` with the derivedOwner.
//! 4. Wallet folds the per-SU ownership records into one
//!    AggregationProofBundle (`aggregate_ownership`).
//! 5. Wallet submits the TributeDraft (`submit_tribute_draft`).
//! 6. Wallet generates the post-mint FullProof (`generate_full_proof`).

use alloy::primitives::{FixedBytes, U256};
use pso_l2_client::artifacts::SuOwnershipRecord;
use pso_l2_client::wallet::{AggregateInputs, FullProofTributeDraft, MerklePathElementInput};
use pso_l2_client::{sra, wallet, L2Client};
use pso_l2_e2e_tests::{random_id, random_secret_key, rpc_url, ADMIN_SECRET_KEY, DEVNET_CHAIN_ID};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("PSO_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

#[tokio::test]
#[ignore = "requires a running PSO L2 node — opt-in via `cargo test -- --ignored`"]
async fn sra_then_wallet_full_flow() -> eyre::Result<()> {
    init_tracing();

    let rpc = rpc_url();
    let sra_client = L2Client::connect_with_signer(&rpc, DEVNET_CHAIN_ID, &ADMIN_SECRET_KEY)?;
    let wallet_key = random_secret_key();
    let wallet_client = L2Client::connect_with_signer(&rpc, DEVNET_CHAIN_ID, &wallet_key)?;

    // -----------------------------------------------------------------
    // 1. SRA: register two spending records.
    // -----------------------------------------------------------------
    let sr1_id = random_id();
    let sr2_id = random_id();
    let sr_tx_1 = sra::register_spending_record(
        &sra_client,
        sr1_id,
        vec!["merchant".to_string(), "amount".to_string()],
        vec![
            FixedBytes::from([0xa1u8; 32]),
            FixedBytes::from([0xa2u8; 32]),
        ],
    )
    .await?;
    tracing::info!(?sr_tx_1, sr_id = ?sr1_id, "SR #1 submitted");

    let sr_tx_2 = sra::register_spending_record(
        &sra_client,
        sr2_id,
        vec!["merchant".to_string(), "amount".to_string()],
        vec![
            FixedBytes::from([0xb1u8; 32]),
            FixedBytes::from([0xb2u8; 32]),
        ],
    )
    .await?;
    tracing::info!(?sr_tx_2, sr_id = ?sr2_id, "SR #2 submitted");

    // -----------------------------------------------------------------
    // 2. SRA: register one amendment record.
    // -----------------------------------------------------------------
    let ar_id = random_id();
    let ar_tx = sra::register_amendment_record(
        &sra_client,
        ar_id,
        vec!["correction".to_string()],
        vec![FixedBytes::from([0xc1u8; 32])],
    )
    .await?;
    tracing::info!(?ar_tx, ar_id = ?ar_id, "AR submitted");

    // -----------------------------------------------------------------
    // 3. Per SU: wallet rolls (nonce, derivedOwner); SRA mints.
    // -----------------------------------------------------------------
    const N_SUS: usize = 2;
    let mut ownership_records: Vec<SuOwnershipRecord> = Vec::with_capacity(N_SUS);
    let mut su_ids: Vec<U256> = Vec::with_capacity(N_SUS);

    for i in 0..N_SUS {
        let su_id = random_id();
        let record = wallet::prepare_su_ownership(&wallet_key, su_id)?;
        let derived_owner_b32 = parse_b32(&record.derived_owner)?;

        let mint_args = sra::MintSpendingUnitArgs {
            su_id,
            derived_owner: derived_owner_b32,
            settlement_currency: 978, // EUR
            worldwide_day: 1825,      // 2026-01-01 — placeholder
            settlement_amount_base: 100 + (i as u64 * 10),
            settlement_amount_atto: 0,
            sr_ids: vec![sr1_id, sr2_id],
            amendment_sr_ids: vec![ar_id],
        };
        let mint_tx = sra::mint_spending_unit(&sra_client, mint_args).await?;
        tracing::info!(?mint_tx, ?su_id, "SU minted");

        ownership_records.push(record);
        su_ids.push(su_id);
    }

    // -----------------------------------------------------------------
    // 4. Wallet aggregates the per-SU ownership records into one proof.
    // -----------------------------------------------------------------
    let tribute_draft_id = random_id();
    let aggregation = wallet::aggregate_ownership(AggregateInputs {
        secret_key: &wallet_key,
        records: &ownership_records,
        su_ids: &su_ids,
        tribute_draft_id,
        chain_id: DEVNET_CHAIN_ID,
    })?;
    assert_eq!(aggregation.tier.tier_n, 2, "tier should match N_SUS=2");
    tracing::info!(
        tier_n = aggregation.tier.tier_n,
        label = %aggregation.tier.label,
        "aggregation proof built"
    );

    // -----------------------------------------------------------------
    // 5. Wallet submits the TributeDraft on L2.
    // -----------------------------------------------------------------
    let td_tx = wallet::submit_tribute_draft(&wallet_client, &aggregation).await?;
    tracing::info!(?td_tx, ?tribute_draft_id, "TributeDraft submitted");

    // -----------------------------------------------------------------
    // 6. Wallet generates the post-mint FullProof for the TD.
    //
    // The wallet keeps the TD-level nonce private; for the test we
    // synthesize a fresh nonce (matches what the wallet does in
    // `aggregate_ownership`). The Merkle path is empty for this
    // standalone test — real usage queries the chain's TD set.
    // -----------------------------------------------------------------
    // Re-derive the TD nonce by mirroring `aggregate_ownership`'s
    // randomness path: the bundle's `td_derived_owner` is a Poseidon5
    // commitment but the test doesn't have access to the wallet's
    // internal nonce. For the e2e demo we generate a fresh one and
    // tie a synthetic FullProof to it.
    let td_nonce_bytes = random_secret_key(); // 32 random bytes — fine as an Fr seed.
    let td_nonce_hex = format!("0x{}", hex::encode(td_nonce_bytes));
    let td_derived_owner_hex = {
        // Re-derive the matching derivedOwner so the full proof is
        // self-consistent.
        let sk = k256::SecretKey::from_slice(&wallet_key)?;
        let nonce = ark_ff::PrimeField::from_le_bytes_mod_order(&td_nonce_bytes);
        let owner = pso_integrations_shared::witness::ownership_from_secret_key(&sk, nonce)
            .map_err(|e| eyre::eyre!("ownership: {e}"))?;
        format!(
            "0x{}",
            hex::encode(pso_integrations_shared::witness::fr_to_le32(&owner))
        )
    };

    let td_record = FullProofTributeDraft {
        tribute_draft_id: format!("0x{:064x}", tribute_draft_id),
        td_derived_owner: td_derived_owner_hex,
        td_nonce: td_nonce_hex,
        settlement_currency: 978,
        worldwide_day: 1825,
        settlement_amount_base: 200,
        settlement_amount_atto: 0,
        su_ids: su_ids.iter().map(|id| format!("0x{:064x}", id)).collect(),
    };
    let merkle_path: Vec<MerklePathElementInput> = vec![]; // empty path → root computed against zero siblings.

    let full_proof = wallet::generate_full_proof(&wallet_key, &td_record, &merkle_path)?;
    assert!(
        !full_proof.public_inputs.is_empty(),
        "full proof must expose public inputs"
    );
    tracing::info!(
        public_inputs = full_proof.public_inputs.len(),
        proof_len = full_proof.proof_bytes_hex.len() / 2 - 1,
        "FullProof generated"
    );

    Ok(())
}

fn parse_b32(s: &str) -> eyre::Result<FixedBytes<32>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    let mut arr = [0u8; 32];
    if bytes.len() != 32 {
        eyre::bail!("expected 32 bytes, got {}", bytes.len());
    }
    arr.copy_from_slice(&bytes);
    Ok(FixedBytes::from(arr))
}
