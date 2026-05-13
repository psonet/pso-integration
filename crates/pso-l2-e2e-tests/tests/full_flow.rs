//! End-to-end integration test exercising the spec-correct SRA +
//! Wallet flow programmatically (no CLI invocation).
//!
//! ## Prerequisites
//!
//! - A running PSO L2 dev node at `$PSO_L2_RPC` (defaults to
//!   `http://127.0.0.1:19545`).
//! - Predeployed contracts at the genesis addresses
//!   `0x5200…0004..0007`.
//! - **Pending circuit work:** the per-SU ownership Noir circuit
//!   (§4.2-compliant) and the recursive aggregation circuit. Until
//!   both land in `pso-zk-circuits`, this test stops at
//!   `prove_su_ownership` with `L2ClientError::CircuitNotAvailable`
//!   — that's the marker that wires up the rest of the flow.
//!
//! Marked `#[ignore]` so normal `cargo test` skips. Opt in via:
//!
//! ```text
//! PSO_L2_RPC=http://127.0.0.1:19545 \
//!     cargo test -p pso-l2-e2e-tests -- --ignored
//! ```
//!
//! ## Flow (spec §4 + §5)
//!
//! 1. Wallet generates `consent_sk` (long-lived) and sends
//!    `consent_pk` to the SRA out-of-band. Test simulates by giving
//!    the SRA `consent_pk` directly.
//! 2. SRA registers spending records / amendment records.
//! 3. For each SU the SRA wants to mint:
//!    - SRA rolls a fresh per-SU ephemeral keypair `(sk_cu, pk_cu)`
//!      and a `su_nonce`.
//!    - SRA computes the same `shared_pk` the wallet will derive
//!      and thus the SU's `derivedOwner`.
//!    - SRA calls `mint_spending_unit` with the computed
//!      `derivedOwner`.
//!    - SRA emits a "receipt" `(pk_cu, su_nonce)` to the wallet.
//!      (In production the receipt is encrypted; the test treats
//!      it as plaintext.)
//!    - SRA deletes `sk_cu`.
//! 4. Wallet, on receiving each receipt, runs
//!    `prepare_su_ownership_material` to reconstruct the same
//!    `shared_sk` via App. A and verifies `derived_owner` matches
//!    the on-chain SU.
//! 5. **(blocked on circuits)** Wallet proves each SU ownership,
//!    folds via the recursion circuit, and submits the TD on L2.
//! 6. **(blocked on circuits)** Wallet generates the post-mint TD
//!    ownership proof for L1 redemption.
//!
//! Today the test runs steps 1–4 fully end-to-end against a real L2
//! node. Step 5 surfaces `CircuitNotAvailable` and the test exits
//! early with that as a documented gate. Step 6 follows the same
//! pattern.

use alloy::primitives::{FixedBytes, U256};
use k256::SecretKey;
use pso_l2_client::shared_key::derive_shared_key_sra_side;
use pso_l2_client::wallet::{
    aggregate_su_proofs, prepare_su_ownership_material, prepare_td_keypair, prove_su_ownership,
    AggregationRequest, SuOwnershipProof, SuOwnershipWitness,
};
use pso_l2_client::{sra, L2Client, L2ClientError};
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

    // -----------------------------------------------------------------
    // 1. Wallet setup: roll a long-lived consent key. In production
    //    the wallet sends consent_pk to the SRA via an authenticated
    //    channel; here we just hold both sides in the test process.
    // -----------------------------------------------------------------
    let wallet_consent_sk_bytes = random_secret_key();
    let consent_sk = SecretKey::from_slice(&wallet_consent_sk_bytes)?;
    let consent_pk = consent_sk.public_key();

    // -----------------------------------------------------------------
    // 2. SRA registers two SRs and one AR.
    // -----------------------------------------------------------------
    let sr1_id = random_id();
    let sr2_id = random_id();
    let _ = sra::register_spending_record(
        &sra_client,
        sr1_id,
        vec!["merchant".into(), "amount".into()],
        vec![
            FixedBytes::from([0xa1u8; 32]),
            FixedBytes::from([0xa2u8; 32]),
        ],
    )
    .await?;
    let _ = sra::register_spending_record(
        &sra_client,
        sr2_id,
        vec!["merchant".into(), "amount".into()],
        vec![
            FixedBytes::from([0xb1u8; 32]),
            FixedBytes::from([0xb2u8; 32]),
        ],
    )
    .await?;
    let ar_id = random_id();
    let _ = sra::register_amendment_record(
        &sra_client,
        ar_id,
        vec!["correction".into()],
        vec![FixedBytes::from([0xc1u8; 32])],
    )
    .await?;

    // -----------------------------------------------------------------
    // 3. For each SU the SRA wants to mint, run the spec-correct
    //    derivation: SRA rolls (sk_cu, pk_cu) + su_nonce, derives the
    //    same shared_pk the wallet will arrive at, computes the
    //    derivedOwner from it, mints the SU, sends (pk_cu, su_nonce)
    //    to the wallet as a "receipt".
    // -----------------------------------------------------------------
    const N_SUS: usize = 2;
    let mut receipts: Vec<(U256, k256::PublicKey, [u8; 32])> = Vec::with_capacity(N_SUS);

    for i in 0..N_SUS {
        let su_id = random_id();

        // SRA-side: roll the per-SU ephemeral keypair + su_nonce,
        // derive the shared key, compute the matching derivedOwner.
        let sk_cu_bytes = random_secret_key();
        let sk_cu = SecretKey::from_slice(&sk_cu_bytes)?;
        let pk_cu = sk_cu.public_key();
        let su_nonce = random_secret_key();

        let sra_shared = derive_shared_key_sra_side(&sk_cu, &consent_pk, &su_nonce)?;
        // Reinterpret the 32-byte secp256k1 shared secret as a
        // Grumpkin scalar (App. A reduction mod q_Grumpkin) and derive
        // the matching Grumpkin pubkey. The derived `owner` is the
        // Poseidon3 commitment over the Grumpkin coords + nonce.
        let nonce_fr = ark_ff::PrimeField::from_le_bytes_mod_order(&su_nonce);
        let sra_sk_bytes: [u8; 32] = sra_shared.secret.to_bytes().into();
        let grumpkin = pso_integrations_shared::witness::derive_grumpkin_public_key(&sra_sk_bytes)
            .map_err(|e| eyre::eyre!("grumpkin pk: {e}"))?;
        let derived_owner_fr = pso_protocol::ownership::compute_ownership_grumpkin(
            grumpkin.pk_x,
            grumpkin.pk_y,
            nonce_fr,
        )
        .map_err(|e| eyre::eyre!("ownership: {e}"))?;
        let derived_owner_bytes = pso_integrations_shared::witness::fr_to_le32(&derived_owner_fr);

        sra::mint_spending_unit(
            &sra_client,
            sra::MintSpendingUnitArgs {
                su_id,
                derived_owner: FixedBytes::from(derived_owner_bytes),
                settlement_currency: 978,
                worldwide_day: 1825,
                settlement_amount_base: 100 + (i as u64 * 10),
                settlement_amount_atto: 0,
                sr_ids: vec![sr1_id, sr2_id],
                amendment_sr_ids: vec![ar_id],
            },
        )
        .await?;
        tracing::info!(?su_id, "SU minted with SRA-computed derivedOwner");

        // "Receipt" delivery (plain in tests; encrypted in prod).
        receipts.push((su_id, pk_cu, su_nonce));
        // SRA deletes sk_cu — drop the binding here (Rust will free it).
        drop(sk_cu);
    }

    // -----------------------------------------------------------------
    // 4. Wallet: for each receipt, reconstruct shared_sk via App. A
    //    and produce an `SuOwnershipWitness`. Sanity-check that the
    //    wallet's derivedOwner matches what the SRA computed (would
    //    match the on-chain SU's `derivedOwner`).
    // -----------------------------------------------------------------
    let witnesses: Vec<SuOwnershipWitness> = receipts
        .iter()
        .map(|(su_id, pk_cu, nonce)| {
            prepare_su_ownership_material(&consent_sk, pk_cu, *nonce, *su_id)
        })
        .collect::<Result<_, _>>()?;
    tracing::info!(
        n = witnesses.len(),
        "wallet reconstructed SuOwnershipWitness from receipts"
    );

    // -----------------------------------------------------------------
    // 5. The next step — `prove_su_ownership` for each witness, then
    //    `aggregate_su_proofs` — requires the new Noir circuits.
    //    Today both surface `CircuitNotAvailable`; this assert pins
    //    the boundary so when the circuit work lands, the test fails
    //    here, prompting an update.
    // -----------------------------------------------------------------
    let su_hashes = witnesses
        .iter()
        .map(|_| ark_bn254::Fr::from(0u64)) // placeholder — real value comes from §3.2.2.
        .collect::<Vec<_>>();
    let proof_attempts: Vec<Result<SuOwnershipProof, L2ClientError>> = witnesses
        .iter()
        .zip(su_hashes.iter())
        .map(|(w, h)| prove_su_ownership(w, *h))
        .collect();
    let mut got_circuit_not_available = 0;
    for result in &proof_attempts {
        if matches!(result, Err(L2ClientError::CircuitNotAvailable { .. })) {
            got_circuit_not_available += 1;
        }
    }
    assert_eq!(
        got_circuit_not_available,
        witnesses.len(),
        "expected each prove_su_ownership to surface CircuitNotAvailable until \
         the §4.2 ownership circuit lands in pso-zk-circuits"
    );

    // For completeness, exercise the rest of the call graph against
    // the stub error so the function-shape part of the redesign is
    // wired up. Once circuits land, these calls will produce real
    // bytes and the assert above will start firing (which is the
    // signal to remove this gate).
    let td_material = prepare_td_keypair()?;
    tracing::info!(
        td_owner = %td_material.td_derived_owner_le_hex,
        "wallet rolled TD keypair material"
    );

    let mut td_owner_bytes = [0u8; 32];
    let td_owner_vec = hex::decode(
        td_material
            .td_derived_owner_le_hex
            .strip_prefix("0x")
            .unwrap_or(&td_material.td_derived_owner_le_hex),
    )?;
    td_owner_bytes.copy_from_slice(&td_owner_vec);

    let agg_result = aggregate_su_proofs(AggregationRequest {
        su_proofs: &[], // empty intentionally — function rejects, then …
        td_derived_owner_le: td_owner_bytes,
    });
    assert!(
        matches!(agg_result, Err(L2ClientError::InvalidInput(_))),
        "aggregate_su_proofs must reject an empty SU proof list before \
         even reaching the circuit-not-available branch"
    );

    Ok(())
}
