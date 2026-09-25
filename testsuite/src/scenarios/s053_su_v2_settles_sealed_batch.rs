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
//! Then the two refusals that make a batch settle once: the same context
//! again, and the same seal id moved to a fresh context.

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

fn seal(ctx: B256, seal_id: B256, group_key: Vec<u8>) -> ISpendingUnitV2::Seal {
    ISpendingUnitV2::Seal {
        ctx,
        sealId: seal_id,
        fsEpoch: 1,
        worldwideDay: BATCH_WWD,
        count: 42,
        fFold: keccak256("S053 f_fold"),
        fsGroupKey: group_key.into(),
        commitmentRoot: keccak256("S053 commitment root").to_vec().into(),
        sequence: 7,
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

    let ctx = keccak256("S053 loader context");
    let seal_id = keccak256("S053 seal attempt");
    let batch = seal(ctx, seal_id, group_key.clone());

    let mint = ISpendingUnitV2::Mint {
        suId: U256::from_be_bytes(keccak256("S053 su id").0) >> 8, // < field modulus
        derivedOwner: keccak256("S053 derived owner"),
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
        su.batches(ctx).call().await?,
        "the context must be consumed"
    );

    // The same batch again, under a fresh SU id: the context is spent.
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
        "a second SU for the same context must be refused"
    );

    // The handle moved to a fresh context: the seal id is spent too, which is
    // what stops a certificate being reused across batches. A new context
    // needs a new handle signature, so the committee signs the moved seal.
    let moved = seal(keccak256("S053 another context"), seal_id, group_key);
    let moved_mint = ISpendingUnitV2::Mint {
        suId: mint.suId + U256::from(2u64),
        ..mint
    };
    let moved_handle =
        sig_g1_eip2537(&committee.sign(&handle_message(attester, &moved), SEAL_DST, &[]));
    let moved_settle = enclave_sk
        .sign(&settlement_message(&moved_mint, &moved, rm_digest()))
        .to_bytes()
        .to_vec();
    let moved_result = su
        .submitSU(moved_mint, moved, moved_handle.into(), moved_settle.into())
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await;
    eyre::ensure!(
        moved_result.is_err(),
        "a seal id replayed under another context must be refused"
    );
    Ok(())
}
