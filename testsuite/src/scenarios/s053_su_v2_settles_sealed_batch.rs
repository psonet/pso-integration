//! S053 — a sealed batch settles into a SpendingUnit v2, and only once.
//!
//! The whole chain of custody the earlier scenarios built, exercised in one
//! transaction: the deployment S052 registered, the committee key S051's
//! epoch 1 installed, a handle that committee signed for each claim pool of
//! the sync, and the enclave's one settlement over the batch totals and the
//! amount. `submitSU` verifies all of it in the EVM — EIP-2537 pairings for
//! each handle, `0x0208` for the settlement — and mints one SU for the
//! batch, which is the first time `FsEpochRegistry.keyFor` has an on-chain
//! consumer.
//!
//! Settlement is once per loader context. The same batch again is refused,
//! and so is a sibling sync of the same context — a re-run from the same
//! cursor seals the same pools under the next sequence — and the refusal
//! names the settlement that won. A batch with a pool dropped no longer adds
//! up to what the enclave signed.

use alloy_primitives::{address, keccak256, Address, B256, U256};
use alloy_provider::Provider;
use async_trait::async_trait;
use ed25519_dalek::Signer as _;

use super::registries::{
    committee_key, enclave_key, handle_message, seal_id, settlement_id, settlement_message,
    sig_g1_eip2537, ISpendingUnitV2, BATCH_WWD, COMMITTEE_SK_IKM_NEXT, SEAL_DST,
};
use super::s052_enclave_registered_for_attester::{provider_id, rm_digest};
use crate::{Scenario, TestEnv};

/// The canonical predeploy (`pso_chain_abi::addresses::SPENDING_UNIT_V2`).
const SPENDING_UNIT_V2: Address = address!("5200000000000000000000000000000000000008");

/// The committee epoch (S051's epoch 1) that signs every handle here.
const FS_EPOCH: u32 = 1;
/// The sync that settles.
const SEQUENCE: u64 = 7;

pub struct S053;

#[async_trait]
impl Scenario for S053 {
    fn id(&self) -> &'static str {
        "S053"
    }
    fn description(&self) -> &'static str {
        "a two-pool sealed batch mints one SU v2, and its context cannot settle twice"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

/// A canonical field element derived from `label`.
///
/// The entity encoding folds `bytes32` roles as field elements and REJECTS a
/// word at or above the BN254 modulus with `NonCanonicalFieldElement` rather
/// than reducing it. A raw keccak output is uniformly random over 2^256, so it
/// clears the modulus roughly four times in five — shifting right by 8 bits
/// puts it below 2^248 and therefore always inside the field, while keeping one
/// distinct value per label.
fn field_element(label: &str) -> B256 {
    B256::from(U256::from_be_bytes(keccak256(label).0) >> 8)
}

/// Two claim pools of one sync: the records settled across a week boundary,
/// so pool 0 is a week older than pool 1. Both certified by epoch 1's
/// committee.
fn pools() -> Vec<ISpendingUnitV2::Seal> {
    [
        (0, BATCH_WWD - 7, 30, "S053 pool 0 fold"),
        (1, BATCH_WWD, 12, "S053 pool 1 fold"),
    ]
    .into_iter()
    .map(|(pool, day, count, fold)| ISpendingUnitV2::Seal {
        poolEpoch: pool,
        fsEpoch: FS_EPOCH,
        worldwideDay: day,
        count,
        fFold: field_element(fold),
        handleSig: Default::default(),
    })
    .collect()
}

/// The committee's handles for `seals` under the ids the chain derives for
/// `(ctx, sequence)`, issued to `attester`.
fn sign_handles(
    committee: &blst::min_sig::SecretKey,
    attester: Address,
    ctx: B256,
    sequence: u64,
    seals: &mut [ISpendingUnitV2::Seal],
) {
    for seal in seals {
        let message = handle_message(attester, ctx, seal_id(ctx, sequence, seal), seal);
        seal.handleSig = sig_g1_eip2537(&committee.sign(&message, SEAL_DST, &[])).into();
    }
}

/// The batch `seals` add up to, with the enclave's settlement over it.
fn settled_batch(
    enclave: &ed25519_dalek::SigningKey,
    mint: &ISpendingUnitV2::Mint,
    ctx: B256,
    sequence: u64,
    seals: &[ISpendingUnitV2::Seal],
) -> ISpendingUnitV2::Batch {
    let mut batch = ISpendingUnitV2::Batch {
        ctx,
        sequence,
        commitmentRoot: keccak256("S053 commitment root").to_vec().into(),
        worldwideDay: seals.iter().map(|s| s.worldwideDay).max().unwrap_or(0),
        count: seals.iter().map(|s| s.count).sum(),
        // Each fold is below 2^248, so two of them sum below the BN254
        // modulus and the chain's `addmod` reduces nothing.
        fFold: B256::from(
            seals
                .iter()
                .map(|s| U256::from_be_bytes(s.fFold.0))
                .fold(U256::ZERO, |a, b| a + b),
        ),
        settleSig: Default::default(),
    };
    batch.settleSig = enclave
        .sign(&settlement_message(mint, &batch, rm_digest()))
        .to_bytes()
        .to_vec()
        .into();
    batch
}

async fn submit<P: Provider>(
    su: &ISpendingUnitV2::ISpendingUnitV2Instance<P>,
    mint: &ISpendingUnitV2::Mint,
    batch: &ISpendingUnitV2::Batch,
    seals: &[ISpendingUnitV2::Seal],
) -> Result<(), alloy_contract::Error> {
    su.submitSU(mint.clone(), batch.clone(), seals.to_vec())
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await?
        .get_receipt()
        .await?;
    Ok(())
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let (enclave_sk, enclave_pk) = enclave_key();
    let committee = committee_key(&COMMITTEE_SK_IKM_NEXT); // epoch 1's key
    let attester = env.attester_zero.address();
    let su = ISpendingUnitV2::new(
        SPENDING_UNIT_V2,
        env.attester_zero.inner().write_provider()?,
    );

    let ctx = field_element("S053 loader context");
    let mint = ISpendingUnitV2::Mint {
        suId: U256::from_be_bytes(keccak256("S053 su id").0) >> 8, // < field modulus
        derivedOwner: field_element("S053 derived owner"),
        referrerAddress: Address::ZERO,
        enclavePk: enclave_pk,
        providerId: provider_id(),
        currency: 978,
        amountBase: 1_234,
        amountAtto: 567_890_000_000_000_000,
    };
    let mut seals = pools();
    sign_handles(&committee, attester, ctx, SEQUENCE, &mut seals);
    let batch = settled_batch(&enclave_sk, &mint, ctx, SEQUENCE, &seals);
    let settled = settlement_id(ctx, SEQUENCE);

    // 1. Both pools settle as one SU.
    if !su.exists(mint.suId).call().await? {
        submit(&su, &mint, &batch, &seals).await?;
    }

    // What the chain stored is what the committee and the enclave stated, not
    // what the submitter typed: the day is the latest pool's, the amount the
    // settlement's, the attester `msg.sender`.
    let entity = su.getData(mint.suId).call().await?;
    eyre::ensure!(
        entity.attesterAddress == attester,
        "the SU must record the submitting attester"
    );
    eyre::ensure!(
        entity.worldwideDay == BATCH_WWD,
        "the SU must record the latest pool's day"
    );
    eyre::ensure!(
        entity.amountBase == mint.amountBase && entity.amountAtto == mint.amountAtto,
        "the SU must record the settled amount"
    );
    eyre::ensure!(
        entity.ctx == ctx && entity.sealId == settled,
        "the SU must name the batch's settlement"
    );
    eyre::ensure!(
        su.settlements(ctx).call().await? == settled,
        "the context must be consumed under the batch's settlement id"
    );

    // 2. The same batch again, under a fresh SU id. The settlement does not
    //    cover the SU id, so the enclave's signature still holds.
    let again = ISpendingUnitV2::Mint {
        suId: mint.suId + U256::from(1u64),
        ..mint.clone()
    };
    expect_already_settled(
        submit(&su, &again, &batch, &seals).await,
        ctx,
        settled,
        "the same batch again",
    )?;

    // 3. A sibling sync of the same context: a re-run from the same cursor
    //    seals the same pools under the next sequence, so every seal id is
    //    new, and the committee and the enclave both sign it. Only one sync
    //    per context settles, and the refusal names the one that did.
    let sibling_mint = ISpendingUnitV2::Mint {
        suId: mint.suId + U256::from(2u64),
        ..mint.clone()
    };
    let mut sibling_seals = pools();
    sign_handles(&committee, attester, ctx, SEQUENCE + 1, &mut sibling_seals);
    let sibling = settled_batch(
        &enclave_sk,
        &sibling_mint,
        ctx,
        SEQUENCE + 1,
        &sibling_seals,
    );
    expect_already_settled(
        submit(&su, &sibling_mint, &sibling, &sibling_seals).await,
        ctx,
        settled,
        "a sibling sync of a settled context",
    )?;

    // 4. A pool dropped: the remaining seal verifies on its own, but no
    //    longer adds up to the totals the enclave signed. Checked before the
    //    context, so it is the same refusal on every run.
    let dropped_mint = ISpendingUnitV2::Mint {
        suId: mint.suId + U256::from(3u64),
        ..mint
    };
    let refused = submit(&su, &dropped_mint, &batch, &seals[..1])
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("a batch with a pool dropped must be refused"))?;
    eyre::ensure!(
        refused
            .as_decoded_error::<ISpendingUnitV2::BatchTotalsMismatch>()
            .is_some(),
        "a dropped pool must be refused as BatchTotalsMismatch: {refused}"
    );
    Ok(())
}

/// `result` must be the chain's `AlreadySettled(ctx, settled)`.
fn expect_already_settled(
    result: Result<(), alloy_contract::Error>,
    ctx: B256,
    settled: B256,
    what: &str,
) -> eyre::Result<()> {
    let refused = result
        .err()
        .ok_or_else(|| eyre::eyre!("{what} must be refused"))?;
    let named = refused
        .as_decoded_error::<ISpendingUnitV2::AlreadySettled>()
        .ok_or_else(|| eyre::eyre!("{what} must be refused as AlreadySettled: {refused}"))?;
    eyre::ensure!(
        named.ctx == ctx && named.settledId == settled,
        "AlreadySettled for {what} must name the context and the settlement that won"
    );
    Ok(())
}
