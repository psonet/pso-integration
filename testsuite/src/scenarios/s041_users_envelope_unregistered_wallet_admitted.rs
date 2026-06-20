//! S041 — users-pool envelope from an UNREGISTERED wallet key is
//! admitted to the pool.
//!
//! Regression test for psonet/pso-chain#13: the actor RPC's pool
//! submitter used to gate every Users-pool transaction's EOA sender
//! against the Attester admission registry, rejecting all genuine wallet
//! submissions with `"Attester not registered: <sender>"` before the VDF
//! was ever verified. The Users lane is permissionless by design —
//! its anti-spam economics are the VDF + nullifier uniqueness +
//! block-age window — so a fresh, never-registered wallet key with a
//! valid envelope MUST clear pool admission.
//!
//! This gate survived CI because every envelope scenario (S013-S017,
//! S031-S032) signs with `env.attester_zero`'s key; this scenario is the
//! one that submits from a key the registry has never seen.
//!
//! Scope: **pool admission only.** The inner calldata is a
//! `TributeDraft.submit(...)` with a bogus aggregation proof, so the
//! EVM-side execution is expected to revert (and pso-chain does not
//! yet strip the 172-byte PSO header before EVM dispatch — see the
//! note in S003). The end-to-end "wallet mints a TD through the
//! actor pool" assertion lands once header-stripping ships; the
//! invariant pinned here is exactly the one #13 fixed:
//!
//!   admission(valid envelope, unregistered sender) != "Attester not registered"

use alloy_primitives::{Bytes, FixedBytes, U256};
use alloy_sol_types::SolCall;
use async_trait::async_trait;

use pso_chain_abi::addresses::TRIBUTE_DRAFT;
use pso_chain_abi::interfaces::ITributeDraft;

use crate::clients::actor::ActorClientError;
use crate::data::random_id;
use crate::{Scenario, TestEnv};

pub struct S041;

#[async_trait]
impl Scenario for S041 {
    fn id(&self) -> &'static str {
        "S041"
    }
    fn description(&self) -> &'static str {
        "users-pool envelope from unregistered wallet key clears pool admission (no Attester gate)"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // Fresh random secp256k1 key — by construction NOT in the Attester
    // registry. The users lane is feeless (zeroed fee caps), so the
    // sender needs no balance either.
    let wallet = env.new_actor()?;

    // Well-formed TD submit with a garbage proof. Pool admission for
    // the users lane validates the ENVELOPE (VDF binding + proof,
    // nullifier, block age) — never the inner calldata, and never the
    // sender's registry status.
    let call = ITributeDraft::submitCall {
        tributeDraftId: random_id(),
        derivedOwner: FixedBytes::<32>::from(U256::from(1).to_be_bytes::<32>()),
        suIds: vec![random_id()],
        aggregationProof: Bytes::from(vec![0u8; 64]),
    };
    let inner = Bytes::from(call.abi_encode());

    match wallet.submit_tx(TRIBUTE_DRAFT, inner).await {
        // Pool admitted the envelope — the fixed behavior. EVM-side
        // outcome (revert on bogus proof / unstripped header) is out
        // of scope here.
        Ok(tx_hash) => {
            tracing::info!(
                ?tx_hash,
                sender = ?wallet.address(),
                "S041: unregistered wallet envelope admitted to pool"
            );
            Ok(())
        }
        // The exact regression #13 fixed.
        Err(ActorClientError::PoolRejection(msg)) if msg.contains("Attester not registered") => {
            Err(eyre::eyre!(
                "S041: REGRESSION — users-pool admission still gates on the Attester \
                 registry (sender {:?}): {msg}. The actor lane must be \
                 permissionless (VDF + nullifier + block age only); see \
                 psonet/pso-chain#13.",
                wallet.address(),
            ))
        }
        // Any other pool rejection is unexpected for a canonical
        // envelope: the client computed a real VDF at the chain's
        // reported difficulty over a fresh head.
        Err(ActorClientError::PoolRejection(msg)) => Err(eyre::eyre!(
            "S041: canonical envelope from fresh wallet rejected by pool: {msg}"
        )),
        Err(other) => Err(eyre::eyre!(
            "S041: submission failed before/at pool admission: {other:?}"
        )),
    }
}
