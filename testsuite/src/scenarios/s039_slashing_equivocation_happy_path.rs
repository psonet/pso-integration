//! S039 — `SlashingVerifier.proveEquivocation` happy path.
//!
//! Construct two distinct block hashes at the same L2 height, sign
//! both with the SRA-0 key, build an `EquivocationProof`, submit.
//! Expect:
//!   * `EquivocationProven(sra_zero, height)`
//!   * `Slashed(sra_zero, Equivocation, proofHash)`
//!
//! Contract behaviour ([`SlashingVerifier.sol::proveEquivocation`]):
//!   1. `blockNumber1 == blockNumber2`
//!   2. `blockHash1 != blockHash2`
//!   3. recover both signers via EIP-191, assert they're equal
//!   4. require `registry.isActive(signer)` — SRA-0 is bootstrap-registered
//!   5. emit events
//!
//! The proof has no bond/revoke side-effect today (Phase 6 of
//! `docs/design/sra-sequencer-rotation.md`); landing the event tail
//! is enough to lock the contract surface in regression.

use alloy::primitives::{Bytes, FixedBytes};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;
use pso_l2_client::abi::{ISlashingVerifier, SLASHING_VERIFIER};

use crate::{Scenario, TestEnv};

pub struct S039;

#[async_trait]
impl Scenario for S039 {
    fn id(&self) -> &'static str {
        "S039"
    }
    fn description(&self) -> &'static str {
        "SlashingVerifier.proveEquivocation: two same-height signatures emit EquivocationProven + Slashed"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // SRA-0's secret bytes live on TestEnv — build a sync signer for
    // local message signing. Reusing the bootstrap-registered SRA
    // means `registry.isActive(signer)` is true without extra setup.
    let signer = PrivateKeySigner::from_slice(&env.sra_zero_key)
        .map_err(|e| eyre::eyre!("S039: signer: {e}"))?;
    let sra = signer.address();

    // Deterministic but distinct hashes at the same height. Real
    // equivocation in the field would produce two genuine block
    // headers; here any pair of distinct 32-byte values works since
    // the contract decides equivocation purely from signature
    // recovery + height equality.
    let height: u64 = 42;
    let hash1: FixedBytes<32> = FixedBytes::from([0x11; 32]);
    let hash2: FixedBytes<32> = FixedBytes::from([0x22; 32]);

    // `signer.sign_message(bytes)` performs the EIP-191 wrap
    // (`"\x19Ethereum Signed Message:\n32" ‖ hash`) that the
    // contract's `_recoverSigner` expects. The resulting signature
    // is 65 bytes (r ‖ s ‖ v).
    let sig1 = signer
        .sign_message_sync(hash1.as_slice())
        .map_err(|e| eyre::eyre!("S039: sign1: {e}"))?;
    let sig2 = signer
        .sign_message_sync(hash2.as_slice())
        .map_err(|e| eyre::eyre!("S039: sign2: {e}"))?;

    let proof = ISlashingVerifier::EquivocationProof {
        blockHash1: hash1,
        blockNumber1: height,
        signature1: Bytes::from(sig1.as_bytes().to_vec()),
        blockHash2: hash2,
        blockNumber2: height,
        signature2: Bytes::from(sig2.as_bytes().to_vec()),
    };

    let write = env.admin.inner().write_provider()?;
    let slashing = ISlashingVerifier::new(SLASHING_VERIFIER, &write);
    let receipt = slashing
        .proveEquivocation(proof)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .map_err(|e| eyre::eyre!("S039: proveEquivocation send: {e}"))?
        .get_receipt()
        .await
        .map_err(|e| eyre::eyre!("S039: receipt: {e}"))?;
    if !receipt.status() {
        return Err(eyre::eyre!(
            "S039: proveEquivocation reverted: {:?}",
            receipt
        ));
    }

    // Walk the receipt logs for the two expected events. Decoding via
    // alloy's generated `SolEvent::decode_log_data` so we get typed
    // structs back rather than raw `Log` objects — keeps the scenario
    // legible and fails loudly if the ABI drifts.
    let mut saw_equivocation = false;
    let mut saw_slashed = false;
    for log in receipt.logs() {
        if let Ok(ev) = ISlashingVerifier::EquivocationProven::decode_log_data(log.data()) {
            if ev.sra == sra && ev.blockNumber == height {
                saw_equivocation = true;
            }
        }
        if let Ok(ev) = ISlashingVerifier::Slashed::decode_log_data(log.data()) {
            // SlashType.Equivocation = 0 (first enum variant).
            if ev.sra == sra && ev.slashType == 0 {
                saw_slashed = true;
            }
        }
    }
    if !(saw_equivocation && saw_slashed) {
        return Err(eyre::eyre!(
            "S039: missing expected events (EquivocationProven={saw_equivocation}, \
             Slashed={saw_slashed})"
        ));
    }

    tracing::info!(
        scenario = "S039",
        sra = %sra,
        height,
        "SlashingVerifier accepted equivocation proof; both expected events emitted",
    );
    Ok(())
}
