//! S001 — full happy-path flow.
//!
//! 1. Wallet derives a `consent` keypair (long-lived) via the mobile FFI
//!    and ships its `consent_pk` (a 32-byte PsoV1 point) out-of-band to
//!    the attester bridge.
//! 2. SRA registers two SRs and one AR per SU it intends to mint.
//! 3. Bridge mints the SUs through the attester FFI, which derives the
//!    matching `derivedOwner` + the wallet's reconstruction material
//!    (the [`IssuanceReport`](pso_mobile_integration::IssuanceReport)).
//! 4. Wallet builds one ownership witness per SU
//!    ([`Consent::witness`](pso_mobile_integration::Consent)) over the
//!    submission `binding`, and confirms each witness's `derivedOwner`
//!    matches the on-chain SU's value (read via `SpendingUnit.getData`).
//! 5. Wallet rolls a per-TD header, aggregates the witnesses into a
//!    flat-aggregation proof ([`Wallet::prove_ownership`]), and submits
//!    `TributeDraft.submit(...)` **itself** through the actor pool — a
//!    fresh non-SRA key, PSO envelope with a real VDF, executed via
//!    TributeDraft's `PsoEnvelopeDispatcher` fallback.
//! 6. Asserts the TD's stored `derivedOwner` matches the wallet's
//!    computation.
//!
//! NOTE: the pre-0.8 suite reconstructed per-SU Grumpkin signing
//! material by hand (App. A ECDH/HKDF) and recomputed the SU hash with
//! `pso_protocol::nft::compute_spending_unit_hash`. The new FFI
//! encapsulates the signer (it never crosses the boundary) and computes
//! the owner / nft_hash internally, so the flow drives the FFI directly
//! rather than recomputing those values by hand.

use std::time::Duration;

use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::SolCall;
use async_trait::async_trait;

use pso_chain_abi::addresses::{SPENDING_UNIT, TRIBUTE_DRAFT};
use pso_chain_abi::interfaces::ITributeDraft;
use pso_protocol::{Codec, PsoV1, Suite};

use crate::bridge::SuMintArgs;
use crate::data::{random_id, random_su_args};
use crate::{Scenario, TestEnv};

type Fr = <PsoV1 as Suite>::Field;

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

// `SpendingUnit.getData(suId)` / `TributeDraft.getData(tdId)` return the
// canonical fields the wallet cross-checks. The `pso-chain-abi`
// interfaces carry `getData`, but the `*Entity` return structs are the
// shape we read below.
async fn run(env: &TestEnv) -> eyre::Result<()> {
    // -----------------------------------------------------------------
    // 1. Wallet setup. The wallet's consent key is long-lived; the
    //    bridge ingests `consent_pk` per SU mint.
    // -----------------------------------------------------------------
    let wallet_ffi = pso_mobile_integration::Wallet::new();
    let consent_seed = vec![0x01u8; 32];
    let consent = wallet_ffi
        .generate_consent(consent_seed.clone())
        .map_err(|e| eyre::eyre!("generate_consent: {e:?}"))?;
    let consent_pk = consent
        .public_key()
        .map_err(|e| eyre::eyre!("consent public_key: {e:?}"))?;

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
        let sr1 = field_id();
        let sr2 = field_id();
        let ar1 = field_id();

        let tx = env.sra_zero.register_spending_record(sr1).await?;
        env.sra_zero
            .wait_for_tx_success(tx, Duration::from_secs(30))
            .await?;

        let tx = env.sra_zero.register_spending_record(sr2).await?;
        env.sra_zero
            .wait_for_tx_success(tx, Duration::from_secs(30))
            .await?;

        let tx = env.sra_zero.register_amendment_record(ar1).await?;
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
    // 3. Bridge mints each SU through the attester FFI. The bridge
    //    handles the consent box + derivedOwner + on-chain
    //    `SpendingUnit.submit`; tests just hand it shapes and get back
    //    the SU id + the issuance report.
    // -----------------------------------------------------------------
    struct LocalReceipt {
        su_id: U256,
        report: pso_attester_integration::IssuanceReport,
    }
    let mut receipts: Vec<LocalReceipt> = Vec::with_capacity(N_SUS);

    // Pin currency + worldwide_day across the two SUs — TD.submit
    // enforces uniformity (`NotSameWorldwideDay` / `NotSameCurrency`).
    let shared_shape = random_su_args();
    for i in 0..N_SUS {
        let args = SuMintArgs {
            consent_pk: consent_pk.clone(),
            // No wallet EVM address in this harness ⇒ no referrer.
            referrer_address: Address::ZERO,
            currency: shared_shape.currency,
            worldwide_day: shared_shape.worldwide_day,
            amount_base: 100 + (i as u64 * 10),
            amount_atto: 0,
            sr_ids: sr_ids_per_su[i].clone(),
            amendment_sr_ids: ar_ids_per_su[i].clone(),
        };
        let r = env.bridge.mint_su(args).await?;
        receipts.push(LocalReceipt {
            su_id: r.su_id,
            report: r.report,
        });
    }

    let su_ids_minted: Vec<U256> = receipts.iter().map(|r| r.su_id).collect();
    env.sra_zero
        .wait_for_su_existence(&su_ids_minted, Duration::from_secs(30))
        .await?;

    // -----------------------------------------------------------------
    // 4. The TD is submitted by a fresh, never-registered per-tx opaque
    //    key whose EOA is `msg.sender` on-chain. Create it BEFORE
    //    proving: the aggregation proof's `binding = Poseidon(sender,
    //    tdId, chainId)` commits to this exact submitter, so it must be
    //    fixed up front and the SAME key must sign the submit below.
    // -----------------------------------------------------------------
    let wallet = env.new_actor()?;
    let sender = wallet.address();
    let chain_id = wallet.chain_id();
    let td_id = random_id();
    let binding =
        PsoV1::binding(&sender.into_array(), &td_id.to_be_bytes::<32>(), chain_id)
            .map_err(|e| eyre::eyre!("compute binding: {e}"))?;
    let binding_bytes = PsoV1::field_to_be_bytes(&binding);

    // -----------------------------------------------------------------
    // 5. Wallet builds one ownership witness per SU over the shared
    //    binding; cross-checks against the on-chain `derivedOwner`.
    // -----------------------------------------------------------------
    let read_provider = env.sra_zero.inner().read_provider();
    let su_view = pso_chain_abi::interfaces::ISpendingUnit::new(SPENDING_UNIT, &read_provider);
    let mut witnesses: Vec<pso_mobile_integration::NftOwnershipWitness> =
        Vec::with_capacity(receipts.len());
    for r in &receipts {
        // Re-shape the attester report into the mobile FFI's report.
        let report = pso_mobile_integration::IssuanceReport {
            nft_id: r.report.nft_id.clone(),
            derived_owner: r.report.derived_owner.clone(),
            nft_hash: r.report.nft_hash.clone(),
            opaque_pk: r.report.opaque_pk.clone(),
            nonce: r.report.nonce.clone(),
        };
        let witness = consent
            .witness(consent_seed.clone(), report, binding_bytes.clone())
            .map_err(|e| eyre::eyre!("consent witness: {e:?}"))?;

        // Read the on-chain SU back and verify the stored `derivedOwner`
        // equals what the wallet's witness asserts. Both are BE.
        let on_chain = su_view.getData(r.su_id).call().await?;
        if on_chain.derivedOwner.as_slice() != witness.derived_owner.as_slice() {
            return Err(eyre::eyre!(
                "S001: on-chain derivedOwner {:?} != wallet-derived {:?} for SU {:#x}",
                on_chain.derivedOwner,
                witness.derived_owner,
                r.su_id
            ));
        }
        witnesses.push(witness);
    }

    // -----------------------------------------------------------------
    // 6. Wallet rolls a TD header (its own owner), aggregates the
    //    witnesses, and submits the TributeDraft via the actor pool.
    // -----------------------------------------------------------------
    let td_header = wallet_ffi
        .generate_nft_header(consent_seed.clone())
        .map_err(|e| eyre::eyre!("td header: {e:?}"))?;
    let td_owner_be = td_header.derived_owner.clone();

    // The flat-aggregation prover wraps barretenberg's FFI; push the
    // synchronous work onto a blocking thread to avoid runtime-in-runtime
    // panics.
    let agg = {
        // `witnesses` is consumed here (not needed afterwards).
        let binding = binding_bytes.clone();
        let seed = consent_seed.clone();
        let wallet_ffi = wallet_ffi.clone();
        tokio::task::spawn_blocking(move || wallet_ffi.prove_ownership(seed, binding, witnesses))
            .await
            .map_err(|e| eyre::eyre!("prove join: {e}"))?
            .map_err(|e| eyre::eyre!("prove_ownership: {e:?}"))?
    };

    let su_ids_ordered: Vec<U256> = su_ids_minted.clone();
    // The chain's `_verifyAggregationProof` expects the `aggregationProof` arg
    // as `[num_inputs:4B BE] ‖ public_inputs(32B × k) ‖ raw_proof`: it parses
    // the prefix, asserts each attested public input matches the value it
    // recomputes (per-SU owner/nft_hash + trailing binding), then forwards the
    // whole blob to the zk_verify precompile. The FFI returns `proof` and
    // `public_inputs` separately, so assemble that wire format here.
    let combined_proof = {
        let k = agg.public_inputs.len();
        let mut buf = Vec::with_capacity(4 + k * 32 + agg.proof.len());
        buf.extend_from_slice(&(k as u32).to_be_bytes());
        for pi in &agg.public_inputs {
            buf.extend_from_slice(pi);
        }
        buf.extend_from_slice(&agg.proof);
        buf
    };
    let inner = ITributeDraft::submitCall {
        tributeDraftId: td_id,
        derivedOwner: FixedBytes::<32>::from_slice(&td_owner_be),
        suIds: su_ids_ordered,
        aggregationProof: Bytes::from(combined_proof),
    }
    .abi_encode();

    let tx = wallet
        .submit_tx(TRIBUTE_DRAFT, Bytes::from(inner))
        .await
        .map_err(|e| eyre::eyre!("wallet-direct TD submit: {e:?}"))?;
    let receipt = wallet.wait_for_receipt(tx, Duration::from_secs(60)).await?;
    if !receipt.status() {
        return Err(eyre::eyre!(
            "S001: wallet-direct TD.submit reverted (tx {tx:#x}) — envelope \
             dispatcher or aggregation verification failed"
        ));
    }

    // -----------------------------------------------------------------
    // 7. Read the TD back, assert the stored `derivedOwner` matches
    //    the wallet's computation (unified BE wire format).
    // -----------------------------------------------------------------
    let td_view = ITributeDraft::new(TRIBUTE_DRAFT, &read_provider);
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

/// A random SR/AR id that is a **canonical field element** — the
/// attester FFI folds these ids into the SU `nft_hash` and rejects any
/// non-canonical (`>=` field modulus) fingerprint. A random `u128`
/// lifted into the field stays safely below the BN254 modulus while
/// remaining collision-free across a session.
fn field_id() -> U256 {
    let f = Fr::from(rand::random::<u128>());
    U256::from_be_slice(&PsoV1::field_to_be_bytes(&f))
}
