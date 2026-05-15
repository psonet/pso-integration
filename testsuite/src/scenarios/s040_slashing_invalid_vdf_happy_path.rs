//! S040 — `SlashingVerifier.proveInvalidVDF` happy path.
//!
//! Submit a deliberately-invalid VDF proof (all-zero output / proof
//! against a non-zero input) attributed to SRA-0. The contract
//! staticcalls the VDF verifier precompile at `0x0200`; since the
//! proof doesn't verify, the precompile returns `false`, the contract
//! accepts the slashing claim, and emits:
//!   * `InvalidVDFProven(sra_zero)`
//!   * `Slashed(sra_zero, InvalidVDF, proofHash)`
//!
//! Contract behaviour ([`SlashingVerifier.sol::proveInvalidVDF`]):
//!   1. `registry.isActive(batchSender)` — SRA-0 is bootstrap-registered
//!   2. staticcall VDF precompile, require result == false
//!   3. emit events; mark `proofHash` as submitted to block double-slash

use alloy::primitives::{Address, Bytes, FixedBytes};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;
use pso_l2_client::abi::{ISlashingVerifier, SLASHING_VERIFIER};

use crate::{Scenario, TestEnv};

pub struct S040;

#[async_trait]
impl Scenario for S040 {
    fn id(&self) -> &'static str {
        "S040"
    }
    fn description(&self) -> &'static str {
        "SlashingVerifier.proveInvalidVDF: zero-bytes proof against non-zero input emits InvalidVDFProven + Slashed"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // SRA-0 is the batchSender claim. The proof itself doesn't need
    // to be sra_zero-attributable — `proveInvalidVDF` just checks
    // (a) batchSender is active and (b) the VDF precompile rejects
    // the supplied (input, output, proof, difficulty) tuple. We use
    // sra_zero because it's the one we know is registered.
    let signer = PrivateKeySigner::from_slice(&env.sra_zero_key)
        .map_err(|e| eyre::eyre!("S040: signer: {e}"))?;
    let sra: Address = signer.address();

    // Construct an obviously-invalid proof: non-zero input, zero
    // output + proof bytes. MinRoot's verifier returns false; the
    // precompile abi-encodes that `false` and the contract accepts
    // the slashing claim.
    let vdf_input: FixedBytes<32> = FixedBytes::from([0x5A; 32]);
    let vdf_output = Bytes::from(vec![0u8; 48]); // MinRoot BLS12-381 output size
    let vdf_proof = Bytes::from(vec![0u8; 48]); // matching proof size
    let difficulty: u64 = 100_000;

    let proof = ISlashingVerifier::InvalidVDFProof {
        vdfInput: vdf_input,
        vdfOutput: vdf_output,
        vdfProof: vdf_proof,
        difficulty,
        batchSender: sra,
    };

    let write = env.admin.inner().write_provider()?;
    let slashing = ISlashingVerifier::new(SLASHING_VERIFIER, &write);
    let receipt = slashing
        .proveInvalidVDF(proof)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await
        .map_err(|e| eyre::eyre!("S040: proveInvalidVDF send: {e}"))?
        .get_receipt()
        .await
        .map_err(|e| eyre::eyre!("S040: receipt: {e}"))?;
    if !receipt.status() {
        return Err(eyre::eyre!("S040: proveInvalidVDF reverted: {:?}", receipt));
    }

    let mut saw_invalid_vdf = false;
    let mut saw_slashed = false;
    for log in receipt.logs() {
        if let Ok(ev) = ISlashingVerifier::InvalidVDFProven::decode_log_data(log.data()) {
            if ev.sra == sra {
                saw_invalid_vdf = true;
            }
        }
        if let Ok(ev) = ISlashingVerifier::Slashed::decode_log_data(log.data()) {
            // SlashType.InvalidVDF = 3 (fourth enum variant).
            if ev.sra == sra && ev.slashType == 3 {
                saw_slashed = true;
            }
        }
    }
    if !(saw_invalid_vdf && saw_slashed) {
        return Err(eyre::eyre!(
            "S040: missing expected events (InvalidVDFProven={saw_invalid_vdf}, \
             Slashed={saw_slashed})"
        ));
    }

    tracing::info!(
        scenario = "S040",
        sra = %sra,
        difficulty,
        "SlashingVerifier accepted invalid-VDF proof; both expected events emitted",
    );
    Ok(())
}
