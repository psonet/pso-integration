//! S051 — the fingerprint-service epoch chain anchors and advances on chain.
//!
//! `FsEpochRegistry` is the chain's copy of the committee key directory, and
//! the only thing it trusts is governance's anchor: every later epoch is
//! admitted because the epoch before it signed the entry. This runs that for
//! real — a BLS12-381 threshold signature verified through the EIP-2537
//! precompiles — and then checks the two refusals that make the chain a chain:
//! an entry the predecessor did not sign, and an entry that skips an epoch.
//!
//! Also the prerequisite for S053: the committee key `submitSU` verifies a
//! seal's handle under is the one installed here.

use alloy_primitives::{keccak256, B256};
use async_trait::async_trait;

use super::registries::{
    committee_key, pk_att_eip2537, sig_g1_eip2537, IFsEpochRegistry, COMMITTEE_SK_IKM,
    COMMITTEE_SK_IKM_NEXT, EPOCH0_START_WWD, EPOCH1_START_WWD, SEAL_DST,
};
use crate::{Scenario, TestEnv};

/// The canonical predeploy (`pso_chain_abi::addresses::FS_EPOCH_REGISTRY`).
const FS_EPOCH_REGISTRY: alloy_primitives::Address =
    alloy_primitives::address!("5200000000000000000000000000000000000003");

pub struct S051;

#[async_trait]
impl Scenario for S051 {
    fn id(&self) -> &'static str {
        "S051"
    }
    fn description(&self) -> &'static str {
        "fs-epoch registry anchors epoch 0 and advances to a predecessor-signed epoch 1"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    let sk0 = committee_key(&COMMITTEE_SK_IKM);
    let sk1 = committee_key(&COMMITTEE_SK_IKM_NEXT);

    let epoch0 = IFsEpochRegistry::Epoch {
        pkAtt: pk_att_eip2537(&sk0).into(),
        dst: SEAL_DST.to_vec().into(),
        startWwd: EPOCH0_START_WWD,
        membersHash: keccak256("S051 committee 0"),
        prevHash: B256::ZERO,
    };

    // Governance anchors epoch 0. Idempotent across reruns against a devnet
    // that already holds it: `anchored()` says so, and re-anchoring reverts.
    let admin = IFsEpochRegistry::new(FS_EPOCH_REGISTRY, env.admin.inner().write_provider()?);
    if !admin.anchored().call().await? {
        admin
            .anchor(epoch0.clone())
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await?
            .get_receipt()
            .await?;
    }
    eyre::ensure!(admin.anchored().call().await?, "epoch 0 must be anchored");

    // Epoch 1, signed by epoch 0's key over `digestOf(1, entry)` — the chain
    // link. `advance` is open to any permitted submitter, so the attester
    // posts it, which is what happens in production.
    let attester = IFsEpochRegistry::new(
        FS_EPOCH_REGISTRY,
        env.attester_zero.inner().write_provider()?,
    );
    if attester.head().call().await? == 0 {
        let entry = IFsEpochRegistry::Epoch {
            pkAtt: pk_att_eip2537(&sk1).into(),
            dst: SEAL_DST.to_vec().into(),
            startWwd: EPOCH1_START_WWD,
            membersHash: keccak256("S051 committee 1"),
            prevHash: admin.digestAt(0).call().await?,
        };
        let digest = admin.digestOf(1, entry.clone()).call().await?;
        let signed = IFsEpochRegistry::SignedEpoch {
            epoch: 1,
            entry: entry.clone(),
            sigPrev: sig_g1_eip2537(&sk0.sign(digest.as_slice(), SEAL_DST, &[])).into(),
        };

        attester
            .advance(vec![signed])
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Epoch 2 signed by epoch 0's key. Epoch 2's predecessor is epoch 1,
        // so this is a stale signer — the forgery the chain rule refuses, and
        // the reason only governance's anchor is trusted outright.
        let forged_entry = IFsEpochRegistry::Epoch {
            startWwd: EPOCH1_START_WWD + 1,
            ..entry
        };
        let forged_digest = admin.digestOf(2, forged_entry.clone()).call().await?;
        let forged = IFsEpochRegistry::SignedEpoch {
            epoch: 2,
            entry: IFsEpochRegistry::Epoch {
                prevHash: admin.digestAt(1).call().await?,
                ..forged_entry
            },
            sigPrev: sig_g1_eip2537(&sk0.sign(forged_digest.as_slice(), SEAL_DST, &[])).into(),
        };
        let refused = attester
            .advance(vec![forged])
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .send()
            .await;
        eyre::ensure!(
            refused.is_err(),
            "an epoch signed by a key that is not the head's must be refused"
        );
    }

    eyre::ensure!(
        attester.head().call().await? == 1,
        "the head must be epoch 1 after the advance"
    );

    // The key the chain now serves for epoch 1 is the successor committee's,
    // and its window opens where the entry said.
    let key = attester.keyFor(1).call().await?;
    eyre::ensure!(
        key.pkAtt.as_ref() == pk_att_eip2537(&sk1).as_slice(),
        "keyFor(1) must return the successor committee's key"
    );
    eyre::ensure!(
        key.dst.as_ref() == SEAL_DST,
        "keyFor(1) must return the tag"
    );
    eyre::ensure!(
        key.startWwd == EPOCH1_START_WWD && key.endWwdExclusive == 0,
        "epoch 1 is the head, so its window is open-ended"
    );
    Ok(())
}
