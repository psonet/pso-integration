//! S001 — full happy-path flow.
//!
//! 1. Wallet rolls a `consent_sk` (long-lived) and ships `consent_pk`
//!    out-of-band to the SRA bridge.
//! 2. SRA registers two SRs and one AR per SU it intends to mint.
//! 3. Bridge mints the SUs, deriving the matching `derivedOwner`
//!    server-side from `(sk_cu, consent_pk, su_nonce)`.
//! 4. Wallet reconstructs every `SuOwnershipWitness` via App. A and
//!    confirms its `derivedOwner` matches the on-chain SU's value
//!    (read back through `SpendingUnit.getData(suId)`).
//! 5. Wallet rolls a per-TD Grumpkin keypair, produces a flat
//!    aggregation proof over the SUs, and broadcasts
//!    `TributeDraft.submit(...)` through the agents pool.
//! 6. Asserts the TD's stored `derivedOwner` matches the wallet's
//!    computation.
//!
//! This is the spec-correct §4 + §5 round-trip; the previous
//! `tests/full_flow.rs` covered the same path inline.

use std::time::Duration;

use alloy::primitives::{FixedBytes, U256};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use async_trait::async_trait;
use k256::SecretKey;

use pso_l2_client::wallet::{
    prepare_su_ownership_material, prepare_td_keypair, submit_tribute_draft, SuAggregationInput,
};

use crate::bridge::SuMintArgs;
use crate::data::{random_id, random_secret_key, random_su_args};
use crate::{Scenario, TestEnv};

/// Unit struct implementing [`Scenario`]; the binary boxes it via
/// `scenarios::all`.
pub struct S001;

#[async_trait]
impl Scenario for S001 {
    fn id(&self) -> &'static str {
        "S001"
    }
    fn description(&self) -> &'static str {
        "full SR/AR -> SU via bridge -> wallet TD prove + submit; derivedOwner round-trip"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

// `SpendingUnit.getData(suId)` / `TributeDraft.getData(tdId)` return
// the canonical fields the wallet needs to cross-check the SRA's
// computation. `pso-l2-client::abi` only exposes `submit`; we declare
// the view slice we need inline.
alloy::sol! {
    /// Mirrors `ISpendingUnit.SpendingUnitEntity` exactly — field order
    /// and types must match the Solidity struct or alloy's ABI decode
    /// rejects with a `type check failed for offset (usize)` because
    /// it interprets a misaligned slot as a dynamic-data offset.
    struct SpendingUnitEntity {
        uint256 suId;
        bytes32 derivedOwner;
        address submittedBy;
        uint256 submittedAt;
        uint32  worldwideDay;
        uint64  settlementAmountBase;
        uint128 settlementAmountAtto;
        uint16  settlementCurrency;
        uint256[] srHashes;
        uint256[] amendmentSrHashes;
    }

    #[sol(rpc)]
    interface ISpendingUnitView {
        function getData(uint256 suId) external view returns (SpendingUnitEntity memory);
    }

    /// Mirrors `ITributeDraft.TributeDraftEntity`. Field order matches
    /// the Solidity struct; see the SU view above for why this matters.
    struct TributeDraftEntity {
        uint256 tdId;
        bytes32 derivedOwner;
        uint16  settlementCurrency;
        uint32  worldwideDay;
        uint64  settlementAmountBase;
        uint128 settlementAmountAtto;
        uint256[] suHashes;
        uint256 createdAt;
    }

    #[sol(rpc)]
    interface ITributeDraftView {
        function getData(uint256 tdId) external view returns (TributeDraftEntity memory);
    }
}

const SPENDING_UNIT_ADDR: alloy::primitives::Address = pso_l2_client::abi::SPENDING_UNIT;
const TRIBUTE_DRAFT_ADDR: alloy::primitives::Address = pso_l2_client::abi::TRIBUTE_DRAFT;

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // -----------------------------------------------------------------
    // 1. Wallet setup. The wallet's consent key is long-lived; the
    //    bridge ingests `consent_pk` per SU mint.
    // -----------------------------------------------------------------
    let consent_sk_bytes = random_secret_key();
    let consent_sk = SecretKey::from_slice(&consent_sk_bytes)?;
    let consent_pk = consent_sk.public_key();

    // -----------------------------------------------------------------
    // 2. SRA registers two SRs + one AR per SU. Each SU consumes a
    //    distinct fingerprint set; sharing across SUs would trip the
    //    `InvalidSpendingRecords` duplicate-SR guard on the second mint.
    // -----------------------------------------------------------------
    const N_SUS: usize = 2;
    let mut sr_ids_per_su: Vec<Vec<U256>> = Vec::with_capacity(N_SUS);
    let mut ar_ids_per_su: Vec<Vec<U256>> = Vec::with_capacity(N_SUS);
    let mut all_sr: Vec<U256> = Vec::new();
    let mut all_ar: Vec<U256> = Vec::new();

    for _ in 0..N_SUS {
        let sr1 = random_id();
        let sr2 = random_id();
        let ar1 = random_id();

        let tx = env
            .sra_zero
            .register_spending_record(
                sr1,
                vec!["merchant".into(), "amount".into()],
                vec![
                    FixedBytes::from([0xa1u8; 32]),
                    FixedBytes::from([0xa2u8; 32]),
                ],
            )
            .await?;
        env.sra_zero
            .wait_for_tx_success(tx, Duration::from_secs(30))
            .await?;

        let tx = env
            .sra_zero
            .register_spending_record(
                sr2,
                vec!["merchant".into(), "amount".into()],
                vec![
                    FixedBytes::from([0xb1u8; 32]),
                    FixedBytes::from([0xb2u8; 32]),
                ],
            )
            .await?;
        env.sra_zero
            .wait_for_tx_success(tx, Duration::from_secs(30))
            .await?;

        let tx = env
            .sra_zero
            .register_amendment_record(
                ar1,
                vec!["correction".into()],
                vec![FixedBytes::from([0xc1u8; 32])],
            )
            .await?;
        env.sra_zero
            .wait_for_tx_success(tx, Duration::from_secs(30))
            .await?;

        sr_ids_per_su.push(vec![sr1, sr2]);
        ar_ids_per_su.push(vec![ar1]);
        all_sr.extend([sr1, sr2]);
        all_ar.push(ar1);
    }
    env.sra_zero
        .wait_for_sr_existence(&all_sr, &all_ar, Duration::from_secs(30))
        .await?;

    // -----------------------------------------------------------------
    // 3. Bridge mints each SU. The bridge handles the `(sk_cu,
    //    pk_cu, su_nonce)` ceremony + derivedOwner commit + on-chain
    //    `SpendingUnit.submit`; tests just hand it shapes.
    // -----------------------------------------------------------------
    struct LocalReceipt {
        su_id: U256,
        pk_cu: k256::PublicKey,
        su_nonce: [u8; 32],
        currency: u16,
        worldwide_day: u32,
        settlement_amount_base: u64,
        settlement_amount_atto: u128,
        sr_ids: Vec<U256>,
        amendment_sr_ids: Vec<U256>,
    }
    let mut receipts: Vec<LocalReceipt> = Vec::with_capacity(N_SUS);

    // Pin currency + worldwide_day across the two SUs — TD.submit
    // enforces uniformity (`NotSameWorldwideDay` /
    // `NotSettlementCurrencyCurrency` otherwise).
    let shared_shape = random_su_args();
    for i in 0..N_SUS {
        let su_id = random_id();
        let args = SuMintArgs {
            su_id,
            consent_pk: consent_pk.clone(),
            currency: shared_shape.currency,
            worldwide_day: shared_shape.worldwide_day,
            settlement_amount_base: 100 + (i as u64 * 10),
            settlement_amount_atto: 0,
            sr_ids: sr_ids_per_su[i].clone(),
            amendment_sr_ids: ar_ids_per_su[i].clone(),
        };
        let r = env.bridge.mint_su(args.clone()).await?;
        receipts.push(LocalReceipt {
            su_id: r.su_id,
            pk_cu: r.pk_cu,
            su_nonce: r.su_nonce,
            currency: args.currency,
            worldwide_day: args.worldwide_day,
            settlement_amount_base: args.settlement_amount_base,
            settlement_amount_atto: args.settlement_amount_atto,
            sr_ids: args.sr_ids,
            amendment_sr_ids: args.amendment_sr_ids,
        });
    }

    let su_ids_minted: Vec<U256> = receipts.iter().map(|r| r.su_id).collect();
    env.sra_zero
        .wait_for_su_existence(&su_ids_minted, Duration::from_secs(30))
        .await?;

    // -----------------------------------------------------------------
    // 4. Wallet reconstructs every `SuOwnershipWitness` from the
    //    receipts; cross-checks against on-chain `derivedOwner`.
    // -----------------------------------------------------------------
    let read_provider = env.sra_zero.inner().read_provider();
    let su_view = ISpendingUnitView::new(SPENDING_UNIT_ADDR, &read_provider);
    let mut su_inputs: Vec<SuAggregationInput> = Vec::with_capacity(receipts.len());
    for r in &receipts {
        let witness = prepare_su_ownership_material(&consent_sk, &r.pk_cu, r.su_nonce, r.su_id)?;

        // Read the on-chain SU back and verify the stored
        // `derivedOwner` equals what the wallet's witness asserts.
        // Both are BE — no byte-swap.
        let on_chain = su_view.getData(r.su_id).call().await?;
        let wallet_owner_be_hex = witness.derived_owner_be_hex.trim_start_matches("0x");
        let wallet_owner_be = hex::decode(wallet_owner_be_hex)?;
        if on_chain.derivedOwner.as_slice() != wallet_owner_be.as_slice() {
            return Err(eyre::eyre!(
                "S001: on-chain derivedOwner {:?} != wallet-derived {:?} for SU {:#x}",
                on_chain.derivedOwner,
                wallet_owner_be,
                r.su_id
            ));
        }

        // Recompute the SU entity hash off-chain; matches the
        // chain's `0x0212` precompile reconstruction.
        let su_id_fr = Fr::from_be_bytes_mod_order(&r.su_id.to_be_bytes::<32>());
        let owner_fr = Fr::from_be_bytes_mod_order(&wallet_owner_be);
        let sr_fps: Vec<Fr> = r
            .sr_ids
            .iter()
            .map(|id| Fr::from_be_bytes_mod_order(&id.to_be_bytes::<32>()))
            .collect();
        let ar_fps: Vec<Fr> = r
            .amendment_sr_ids
            .iter()
            .map(|id| Fr::from_be_bytes_mod_order(&id.to_be_bytes::<32>()))
            .collect();
        let nft_hash = pso_protocol::nft::compute_spending_unit_hash(
            &su_id_fr,
            &owner_fr,
            u64::from(r.worldwide_day),
            r.currency,
            r.settlement_amount_base,
            r.settlement_amount_atto as u64,
            &sr_fps,
            &ar_fps,
        )
        .map_err(|e| eyre::eyre!("compute_spending_unit_hash: {e}"))?;

        let nonce_arr = r.su_nonce;
        let sk_bytes = hex::decode(witness.shared_sk_hex.trim_start_matches("0x"))?;
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes);
        su_inputs.push(SuAggregationInput {
            su_id: format!("0x{:064x}", r.su_id),
            grumpkin_sk: sk_arr,
            nonce: Fr::from_be_bytes_mod_order(&nonce_arr),
            derived_owner: owner_fr,
            nft_hash,
        });
    }

    // -----------------------------------------------------------------
    // 5. Wallet rolls TD keypair, runs the flat-aggregation prover,
    //    submits the TributeDraft.
    // -----------------------------------------------------------------
    let td_material = prepare_td_keypair()?;
    let td_owner_be_hex = td_material.td_derived_owner_be_hex.trim_start_matches("0x");
    let td_owner_be = hex::decode(td_owner_be_hex)?;
    let td_owner_fr = Fr::from_be_bytes_mod_order(&td_owner_be);

    // TD id derivation: the protocol's `compute_tribute_draft_id` is
    // `Poseidon2(owner, wwd)` — out of scope for S001 (we only need a
    // unique id the wallet controls). Pick a random one.
    let td_id = random_id();

    // The flat-aggregation prover wraps `noir_rs` which spins up its
    // own tokio runtime; push the synchronous work onto a blocking
    // thread to avoid runtime-in-runtime panics.
    let bundle = {
        let su_inputs_owned = su_inputs.clone();
        tokio::task::spawn_blocking(move || {
            pso_l2_client::wallet::prove_su_aggregation(&su_inputs_owned, td_id, td_owner_fr)
        })
        .await
        .map_err(|e| eyre::eyre!("prove join: {e}"))??
    };

    let tx = submit_tribute_draft(env.sra_zero.inner(), &bundle).await?;
    env.sra_zero
        .wait_for_tx_success(tx, Duration::from_secs(60))
        .await?;

    // -----------------------------------------------------------------
    // 6. Read the TD back, assert the stored `derivedOwner` matches
    //    the wallet's computation. Unified BE wire format across SU
    //    and TD now, so the on-chain slot is BE and matches the
    //    wallet's bytes verbatim.
    // -----------------------------------------------------------------
    let td_view = ITributeDraftView::new(TRIBUTE_DRAFT_ADDR, &read_provider);
    let td_on_chain = td_view.getData(td_id).call().await?;
    if td_on_chain.derivedOwner.as_slice() != td_owner_be.as_slice() {
        return Err(eyre::eyre!(
            "S001: TD on-chain derivedOwner {:?} != wallet-derived {:?}",
            td_on_chain.derivedOwner,
            td_owner_be
        ));
    }

    Ok(())
}
