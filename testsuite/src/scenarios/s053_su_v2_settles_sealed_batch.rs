//! S053 — a sealed batch settles into a SpendingUnit v2, and only once.
//!
//! The whole chain of custody the earlier scenarios built, exercised in one
//! transaction: the deployment S052 registered, the committee key S051's
//! epoch 1 installed, a handle that committee signed, and the enclave's
//! settlement over the amount. `submitSU` verifies all of it in the EVM —
//! EIP-2537 pairings for the handle, `0x0208` for the settlement — and mints
//! the SU, which is the first time `FsEpochRegistry.keyFor` has an on-chain
//! consumer.
//!
//! Settlement is once per claim pool, `(ctx, poolEpoch)`: the same seal
//! again is refused, and so is a sibling attempt over the same pool — a sync
//! re-run from the same cursor seals the pool again under a new seal id, and
//! the refusal names the attempt that won. A second pool of the same context
//! — a sync whose records settled in two key epochs — settles on its own.

use alloy_primitives::{address, keccak256, Address, B256, U256};
use async_trait::async_trait;
use ed25519_dalek::Signer as _;

use super::registries::{
    committee_key, enclave_key, handle_message, settlement_message, sig_g1_eip2537,
    ISpendingUnitV2, BATCH_WWD, COMMITTEE_SK_IKM_NEXT, SEAL_DST,
};
use super::s052_enclave_registered_for_attester::{provider_id, rm_digest};
use crate::{Scenario, TestEnv};

/// The canonical predeploy (`pso_chain_abi::addresses::SPENDING_UNIT_V2`).
const SPENDING_UNIT_V2: Address = address!("5200000000000000000000000000000000000008");

/// The claim pool the batch was accumulated in: an earlier key epoch than the
/// committee epoch (1) that signs it, as a batch sealed after a rotation is.
const POOL: u32 = 0;

pub struct S053;

#[async_trait]
impl Scenario for S053 {
    fn id(&self) -> &'static str {
        "S053"
    }
    fn description(&self) -> &'static str {
        "a committee-sealed, enclave-settled batch mints one SU v2 and cannot settle twice"
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

fn seal(
    ctx: B256,
    pool: u32,
    seal_id: B256,
    sequence: u64,
    group_key: Vec<u8>,
) -> ISpendingUnitV2::Seal {
    ISpendingUnitV2::Seal {
        ctx,
        sealId: seal_id,
        fsEpoch: 1,
        poolEpoch: pool,
        worldwideDay: BATCH_WWD,
        count: 42,
        fFold: field_element("S053 f_fold"),
        fsGroupKey: group_key.into(),
        commitmentRoot: keccak256("S053 commitment root").to_vec().into(),
        sequence,
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let (enclave_sk, enclave_pk) = enclave_key();
    let committee = committee_key(&COMMITTEE_SK_IKM_NEXT); // epoch 1's key
    let attester = env.attester_zero.address();
    let su = ISpendingUnitV2::new(
        SPENDING_UNIT_V2,
        env.attester_zero.inner().write_provider()?,
    );

    // The seal carries the committee key the enclave verified the handle
    // under, compressed — the form the provider's wire uses. The registry
    // holds the same key in the EIP-2537 layout; `submitSU` verifies under the
    // registry's, and the settlement signature covers this copy.
    let group_key = committee.sk_to_pk().compress().to_vec();

    let ctx = field_element("S053 loader context");
    let seal_id = field_element("S053 seal attempt");
    let batch = seal(ctx, POOL, seal_id, 7, group_key.clone());

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

    let handle_sig =
        sig_g1_eip2537(&committee.sign(&handle_message(attester, &batch), SEAL_DST, &[]));
    let settle_sig = enclave_sk
        .sign(&settlement_message(&mint, &batch, rm_digest()))
        .to_bytes()
        .to_vec();

    if !su.exists(mint.suId).call().await? {
        su.submitSU(
            mint.clone(),
            batch.clone(),
            handle_sig.clone().into(),
            settle_sig.clone().into(),
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await?
        .get_receipt()
        .await?;
    }

    // What the chain stored is what the committee and the enclave stated, not
    // what the submitter typed: the day comes from the handle, the amount from
    // the settlement, the attester from `msg.sender`.
    let entity = su.getData(mint.suId).call().await?;
    eyre::ensure!(
        entity.attesterAddress == attester,
        "the SU must record the submitting attester"
    );
    eyre::ensure!(
        entity.worldwideDay == BATCH_WWD,
        "the SU must record the committee's day"
    );
    eyre::ensure!(
        entity.amountBase == mint.amountBase && entity.amountAtto == mint.amountAtto,
        "the SU must record the settled amount"
    );
    eyre::ensure!(
        entity.ctx == ctx && entity.sealId == seal_id,
        "the SU must name the batch it settled"
    );
    eyre::ensure!(
        su.settledPools(ctx, POOL).call().await? == seal_id,
        "the pool must name the attempt that settled it"
    );

    // The same batch again, under a fresh SU id: the pool is spent.
    let again = ISpendingUnitV2::Mint {
        suId: mint.suId + U256::from(1u64),
        ..mint.clone()
    };
    let replay_settle = enclave_sk
        .sign(&settlement_message(&again, &batch, rm_digest()))
        .to_bytes()
        .to_vec();
    let replayed = su
        .submitSU(
            again.clone(),
            batch.clone(),
            handle_sig.clone().into(),
            replay_settle.into(),
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await;
    eyre::ensure!(
        replayed.is_err(),
        "a second SU for the same seal must be refused"
    );

    // A sibling attempt over the same pool: a re-run from the same cursor
    // seals it again under a new seal id and the next sequence, and the
    // committee and the enclave both sign it. Only one attempt per pool
    // settles, and the refusal names the one that did.
    let sibling = seal(
        ctx,
        POOL,
        field_element("S053 sibling attempt"),
        8,
        group_key.clone(),
    );
    let sibling_mint = ISpendingUnitV2::Mint {
        suId: mint.suId + U256::from(2u64),
        ..mint.clone()
    };
    let sibling_handle =
        sig_g1_eip2537(&committee.sign(&handle_message(attester, &sibling), SEAL_DST, &[]));
    let sibling_settle = enclave_sk
        .sign(&settlement_message(&sibling_mint, &sibling, rm_digest()))
        .to_bytes()
        .to_vec();
    let refused = su
        .submitSU(
            sibling_mint,
            sibling,
            sibling_handle.into(),
            sibling_settle.into(),
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .err()
        .ok_or_else(|| eyre::eyre!("a sibling attempt over a settled pool must be refused"))?;
    let named = refused
        .as_decoded_error::<ISpendingUnitV2::AlreadySettled>()
        .ok_or_else(|| eyre::eyre!("the sibling must be refused as AlreadySettled: {refused}"))?;
    eyre::ensure!(
        named.ctx == ctx && named.poolEpoch == POOL && named.settledSealId == seal_id,
        "AlreadySettled must name the pool and the attempt that won"
    );

    // The next pool of the same context: a sync whose records settled in two
    // key epochs seals one batch per pool under one context, and each settles.
    let next_pool_id = field_element("S053 next pool attempt");
    let next_pool = seal(ctx, POOL + 1, next_pool_id, 7, group_key);
    let next_mint = ISpendingUnitV2::Mint {
        suId: mint.suId + U256::from(3u64),
        ..mint
    };
    if !su.exists(next_mint.suId).call().await? {
        let next_handle =
            sig_g1_eip2537(&committee.sign(&handle_message(attester, &next_pool), SEAL_DST, &[]));
        let next_settle = enclave_sk
            .sign(&settlement_message(&next_mint, &next_pool, rm_digest()))
            .to_bytes()
            .to_vec();
        su.submitSU(
            next_mint.clone(),
            next_pool,
            next_handle.into(),
            next_settle.into(),
        )
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await?
        .get_receipt()
        .await?;
    }
    eyre::ensure!(
        su.settledPools(ctx, POOL + 1).call().await? == next_pool_id,
        "another pool of the same context must settle on its own"
    );
    Ok(())
}
