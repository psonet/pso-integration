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
    prepare_su_ownership_material, prepare_td_keypair, SuAggregationInput, SuOwnershipWitness,
};
use pso_l2_client::{sra, L2Client};
use pso_l2_e2e_tests::{
    random_id, random_secret_key, rpc_url, ADMIN_SECRET_KEY, DEVNET_CHAIN_ID,
    REGISTRY_ADMIN_SECRET_KEY,
};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("PSO_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

alloy::sol! {
    #[sol(rpc)]
    interface ISRARegistry {
        function isActive(address sra) external view returns (bool);
        function register(
            address sra,
            uint32 permissionMask,
            uint64 rateLimit,
            bool isRotationCandidate
        ) external;
    }
}

alloy::sol! {
    #[sol(rpc)]
    interface IExistsLike {
        function exists(uint256 tokenId) external view returns (bool);
    }
}

const SRA_REGISTRY: alloy::primitives::Address =
    alloy::primitives::address!("5200000000000000000000000000000000000001");
const SPENDING_RECORD: alloy::primitives::Address =
    alloy::primitives::address!("5200000000000000000000000000000000000004");
const SPENDING_RECORD_AMENDMENT: alloy::primitives::Address =
    alloy::primitives::address!("5200000000000000000000000000000000000005");
const SPENDING_UNIT: alloy::primitives::Address =
    alloy::primitives::address!("5200000000000000000000000000000000000006");

/// Poll until a tx receipt is available and report failure if status != 0x1.
async fn wait_for_tx_success(rpc: &str, tx_hash: alloy::primitives::TxHash) -> eyre::Result<()> {
    use alloy::providers::Provider;
    let client = L2Client::connect(rpc, DEVNET_CHAIN_ID)?;
    let provider = client.read_provider();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(receipt) = provider.get_transaction_receipt(tx_hash).await? {
            if receipt.status() {
                return Ok(());
            }
            return Err(eyre::eyre!("tx {tx_hash:#x} reverted on-chain"));
        }
        if std::time::Instant::now() >= deadline {
            return Err(eyre::eyre!("timeout: no receipt for {tx_hash:#x}"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

/// Same shape as [`wait_for_sr_existence`], but for SU mints. Used
/// before `TributeDraft.submit` so the contract's `getData(su_id)`
/// (which reverts `NotFound` on `submittedBy == 0`) sees the freshly
/// minted SUs.
async fn wait_for_su_existence(rpc: &str, su_ids: &[U256]) -> eyre::Result<()> {
    let client = L2Client::connect(rpc, DEVNET_CHAIN_ID)?;
    let provider = client.read_provider();
    let su = IExistsLike::new(SPENDING_UNIT, &provider);

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let mut all = true;
        for id in su_ids {
            if !su.exists(*id).call().await? {
                all = false;
                break;
            }
        }
        if all {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "timeout: SU ids not visible on-chain after 30s"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

/// Poll until every passed SR/AR id is observable via the SBT
/// `exists(uint256)` view. Used right after `register_spending_record`
/// / `register_amendment_record` to make sure the downstream SU mint
/// pre-flight doesn't race the inclusion of these txs.
async fn wait_for_sr_existence(
    rpc: &str,
    sr_ids: &[U256],
    ar_ids: &[U256],
) -> eyre::Result<()> {
    let client = L2Client::connect(rpc, DEVNET_CHAIN_ID)?;
    let provider = client.read_provider();
    let sr = IExistsLike::new(SPENDING_RECORD, &provider);
    let ar = IExistsLike::new(SPENDING_RECORD_AMENDMENT, &provider);

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut last_missing: Option<U256> = None;
    loop {
        let mut all = true;
        for id in sr_ids {
            if !sr.exists(*id).call().await? {
                all = false;
                last_missing = Some(*id);
                break;
            }
        }
        if all {
            for id in ar_ids {
                if !ar.exists(*id).call().await? {
                    all = false;
                    last_missing = Some(*id);
                    break;
                }
            }
        }
        if all {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "timeout: SR/AR ids not visible on-chain after 30s. last_missing={:?}",
                last_missing
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

/// Register the test's SRA signer with the genesis admin so the
/// `onlyActiveSRA`-gated submit paths admit it. Idempotent — if
/// already registered we short-circuit (so re-running against a hot
/// node doesn't fail).
async fn bootstrap_register_sra(rpc: &str) -> eyre::Result<()> {
    let sra_client =
        L2Client::connect_with_signer(rpc, DEVNET_CHAIN_ID, &ADMIN_SECRET_KEY)?;
    let sra_addr = sra_client
        .signer_address()
        .ok_or_else(|| eyre::eyre!("SRA signer missing"))?;

    let read_provider = sra_client.read_provider();
    let registry = ISRARegistry::new(SRA_REGISTRY, &read_provider);
    if registry.isActive(sra_addr).call().await? {
        return Ok(());
    }

    let admin_client =
        L2Client::connect_with_signer(rpc, DEVNET_CHAIN_ID, &REGISTRY_ADMIN_SECRET_KEY)?;
    let write_provider = admin_client.write_provider()?;
    let registry_w = ISRARegistry::new(SRA_REGISTRY, &write_provider);
    let pending = registry_w
        .register(sra_addr, u32::MAX, 1_000_000u64, true)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .send()
        .await?;
    pending.get_receipt().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a running PSO L2 node — opt-in via `cargo test -- --ignored`"]
async fn sra_then_wallet_full_flow() -> eyre::Result<()> {
    init_tracing();

    let rpc = rpc_url();

    // -----------------------------------------------------------------
    // 0. Bootstrap the SRA registry. The devnet genesis ships only the
    //    admin slot populated; nothing is pre-registered. The
    //    registry admin (Hardhat #0) registers the SRA signer
    //    (Hardhat #1) with `permissionMask = 0xFFFFFFFF` so every
    //    `onlyActiveSRA`-gated entrypoint (SR / AR / SU / TD submit)
    //    will accept it.
    // -----------------------------------------------------------------
    bootstrap_register_sra(&rpc).await?;
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
    // 2. SRA registers one SR + one AR per SU. The SU contract enforces
    //    fingerprint uniqueness (`usedSpendingRecordIds`), so each SU
    //    must consume a distinct set; sharing across SUs would revert
    //    the second mint with `SpendingRecordsAlreadyExist`.
    // -----------------------------------------------------------------
    const N_SUS: usize = 2;
    let mut sr_ids_per_su: Vec<Vec<U256>> = Vec::with_capacity(N_SUS);
    let mut ar_ids_per_su: Vec<Vec<U256>> = Vec::with_capacity(N_SUS);
    let mut all_sr_ids: Vec<U256> = Vec::with_capacity(N_SUS * 2);
    let mut all_ar_ids: Vec<U256> = Vec::with_capacity(N_SUS);
    for i in 0..N_SUS {
        let sr1_id = random_id();
        let sr2_id = random_id();
        let ar_id = random_id();
        // Wait for each receipt before launching the next: alloy's
        // eth_estimateGas runs against pre-broadcast state and ~4K-gas
        // underestimates back-to-back mints — the second tx runs OOM
        // when the previous one's `_mint` pushed enumerator entries.
        let tx = sra::register_spending_record(
            &sra_client,
            sr1_id,
            vec!["merchant".into(), "amount".into()],
            vec![
                FixedBytes::from([0xa1u8 ^ i as u8; 32]),
                FixedBytes::from([0xa2u8 ^ i as u8; 32]),
            ],
        )
        .await?;
        wait_for_tx_success(&rpc, tx).await?;
        let tx = sra::register_spending_record(
            &sra_client,
            sr2_id,
            vec!["merchant".into(), "amount".into()],
            vec![
                FixedBytes::from([0xb1u8 ^ i as u8; 32]),
                FixedBytes::from([0xb2u8 ^ i as u8; 32]),
            ],
        )
        .await?;
        wait_for_tx_success(&rpc, tx).await?;
        let tx = sra::register_amendment_record(
            &sra_client,
            ar_id,
            vec!["correction".into()],
            vec![FixedBytes::from([0xc1u8 ^ i as u8; 32])],
        )
        .await?;
        wait_for_tx_success(&rpc, tx).await?;
        sr_ids_per_su.push(vec![sr1_id, sr2_id]);
        ar_ids_per_su.push(vec![ar_id]);
        all_sr_ids.extend([sr1_id, sr2_id]);
        all_ar_ids.push(ar_id);
    }

    // The SR/AR `register_*` helpers return after broadcast, not after
    // inclusion. SU mint's pre-flight (`eth_estimateGas` -> ownership
    // check via `spendingRecord.exists(h)`) runs against the head, so
    // we wait for the records to actually be mined before continuing.
    wait_for_sr_existence(&rpc, &all_sr_ids, &all_ar_ids).await?;

    // -----------------------------------------------------------------
    // 3. For each SU the SRA wants to mint, run the spec-correct
    //    derivation: SRA rolls (sk_cu, pk_cu) + su_nonce, derives the
    //    same shared_pk the wallet will arrive at, computes the
    //    derivedOwner from it, mints the SU, sends (pk_cu, su_nonce)
    //    to the wallet as a "receipt".
    // -----------------------------------------------------------------
    /// What the SRA emits in the receipt plus the SU-envelope fields
    /// the wallet needs to recompute the SU entity hash off-chain.
    /// In production the receipt only carries `(pk_cu, su_nonce,
    /// encrypted_report)`; the wallet pulls the canonical SU fields
    /// back from L2 via `getData(su_id)`. The test threads them
    /// through directly to avoid a separate read-back round trip.
    struct Receipt {
        su_id: U256,
        pk_cu: k256::PublicKey,
        su_nonce: [u8; 32],
        // Replay of the mint args -- the wallet needs these to call
        // `pso_protocol::nft::compute_spending_unit_hash` and produce
        // the `nft_hash` public input the aggregation proof commits to.
        settlement_currency: u16,
        worldwide_day: u32,
        settlement_amount_base: u64,
        settlement_amount_atto: u128,
        sr_ids: Vec<U256>,
        amendment_sr_ids: Vec<U256>,
    }
    let mut receipts: Vec<Receipt> = Vec::with_capacity(N_SUS);

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
        let sra_sk_raw: [u8; 32] = sra_shared.secret.to_bytes().into();
        let sra_sk_bytes = pso_integrations_shared::witness::reduce_to_grumpkin_sk(&sra_sk_raw);
        let grumpkin = pso_integrations_shared::witness::derive_grumpkin_public_key(&sra_sk_bytes)
            .map_err(|e| eyre::eyre!("grumpkin pk: {e}"))?;
        let derived_owner_fr = pso_protocol::ownership::compute_ownership_grumpkin(
            grumpkin.pk_x,
            grumpkin.pk_y,
            nonce_fr,
        )
        .map_err(|e| eyre::eyre!("ownership: {e}"))?;
        // `derivedOwner` is consumed by (a) the `0x0212` SU-hash
        // precompile (BE-parsed) and (b) the on-chain
        // `_collectSuTotals` step that copies it verbatim into the
        // aggregation proof's public-input vector — which barretenberg
        // serializes as BE. Store BE so both readers see the same Fr.
        let derived_owner_bytes = pso_integrations_shared::witness::fr_to_be32(&derived_owner_fr);

        let su_currency: u16 = 978;
        let su_wwd: u32 = 1825;
        let su_base: u64 = 100 + (i as u64 * 10);
        let su_atto: u128 = 0;
        let sr_ids_vec = sr_ids_per_su[i].clone();
        let ar_ids_vec = ar_ids_per_su[i].clone();

        let mint_hash = sra::mint_spending_unit(
            &sra_client,
            sra::MintSpendingUnitArgs {
                su_id,
                derived_owner: FixedBytes::from(derived_owner_bytes),
                settlement_currency: su_currency,
                worldwide_day: su_wwd,
                settlement_amount_base: su_base,
                settlement_amount_atto: su_atto,
                sr_ids: sr_ids_vec.clone(),
                amendment_sr_ids: ar_ids_vec.clone(),
            },
        )
        .await?;
        // Each SU mint must land before the next one's `eth_estimateGas`
        // runs — otherwise alloy estimates against pre-mint state and
        // the second tx OOMs on its (now larger) `usedSpendingRecordIds`
        // sstore set.
        wait_for_tx_success(&rpc, mint_hash).await?;
        tracing::info!(?su_id, "SU minted with SRA-computed derivedOwner");

        // "Receipt" delivery (plain in tests; encrypted in prod).
        receipts.push(Receipt {
            su_id,
            pk_cu,
            su_nonce,
            settlement_currency: su_currency,
            worldwide_day: su_wwd,
            settlement_amount_base: su_base,
            settlement_amount_atto: su_atto,
            sr_ids: sr_ids_vec,
            amendment_sr_ids: ar_ids_vec,
        });
        // SRA deletes sk_cu — drop the binding here (Rust will free it).
        drop(sk_cu);
    }

    // `mint_spending_unit` returns after broadcast; TD.submit's
    // `getData(su_id)` lookup runs against the head, so we wait for
    // every SU to actually be on-chain before continuing.
    let minted_su_ids: Vec<U256> = receipts.iter().map(|r| r.su_id).collect();
    wait_for_su_existence(&rpc, &minted_su_ids).await?;

    // -----------------------------------------------------------------
    // 4. Wallet: for each receipt, reconstruct shared_sk via App. A
    //    and produce an `SuOwnershipWitness`. Sanity-check that the
    //    wallet's derivedOwner matches what the SRA computed (would
    //    match the on-chain SU's `derivedOwner`).
    // -----------------------------------------------------------------
    let witnesses: Vec<SuOwnershipWitness> = receipts
        .iter()
        .map(|r| prepare_su_ownership_material(&consent_sk, &r.pk_cu, r.su_nonce, r.su_id))
        .collect::<Result<_, _>>()?;
    tracing::info!(
        n = witnesses.len(),
        "wallet reconstructed SuOwnershipWitness from receipts"
    );

    // -----------------------------------------------------------------
    // 5. Wallet rolls a fresh TD-level Grumpkin keypair, then calls
    //    `prove_su_aggregation` over all SUs. One flat-aggregation
    //    prove pass (no per-SU intermediate proofs); the chosen tier
    //    circuit duplicates the per-SU ownership constraint set inline.
    // -----------------------------------------------------------------
    let td_material = prepare_td_keypair()?;
    tracing::info!(
        td_owner = %td_material.td_derived_owner_le_hex,
        "wallet rolled TD keypair material"
    );

    // Assemble per-SU inputs. Each draws on the persisted
    // `SuOwnershipWitness` for the Grumpkin sk + derivedOwner, plus
    // the canonical SU fields (held in the test's `Receipt`) to
    // recompute the entity hash the chain commits to in storage.
    let mut su_inputs: Vec<SuAggregationInput> = Vec::with_capacity(witnesses.len());
    for (w, r) in witnesses.iter().zip(receipts.iter()) {
        let sk_bytes = decode_hex32(&w.shared_sk_hex)?;
        let nonce_arr = decode_hex32(&w.su_nonce_le_hex)?;
        let owner_arr = decode_hex32(&w.derived_owner_le_hex)?;
        let owner_fr = ark_ff::PrimeField::from_le_bytes_mod_order(&owner_arr);

        // SU entity hash per sec. 3.2.3. The chain reconstructs the
        // same value via the 0x0212 precompile from canonical SU
        // storage; both sides absorb (id, owner, wwd, currency, base,
        // atto, sr_fps, ar_fps) into ProtocolHasher identically.
        let su_id_fr = <ark_bn254::Fr as ark_ff::PrimeField>::from_be_bytes_mod_order(&r.su_id.to_be_bytes::<32>());
        let sr_fps: Vec<ark_bn254::Fr> = r
            .sr_ids
            .iter()
            .map(|id| <ark_bn254::Fr as ark_ff::PrimeField>::from_be_bytes_mod_order(&id.to_be_bytes::<32>()))
            .collect();
        let ar_fps: Vec<ark_bn254::Fr> = r
            .amendment_sr_ids
            .iter()
            .map(|id| <ark_bn254::Fr as ark_ff::PrimeField>::from_be_bytes_mod_order(&id.to_be_bytes::<32>()))
            .collect();
        let nft_hash = pso_protocol::nft::compute_spending_unit_hash(
            &su_id_fr,
            &owner_fr,
            u64::from(r.worldwide_day),
            r.settlement_currency,
            r.settlement_amount_base,
            // u128 atto: the precompile + protocol take u64; the spec
            // guarantees atto < 1e18 ≪ 2^60, so the cast is lossless.
            r.settlement_amount_atto as u64,
            &sr_fps,
            &ar_fps,
        )
        .map_err(|e| eyre::eyre!("compute_spending_unit_hash: {e}"))?;

        su_inputs.push(SuAggregationInput {
            su_id: format!("0x{:064x}", parse_u256_hex(&w.su_id)?),
            grumpkin_sk: sk_bytes,
            nonce: ark_ff::PrimeField::from_le_bytes_mod_order(&nonce_arr),
            derived_owner: owner_fr,
            nft_hash,
        });
    }

    let td_id = U256::from_be_bytes(decode_hex32(&format!(
        "{:0>64}",
        td_material.td_derived_owner_le_hex.trim_start_matches("0x")
    ))?);
    let td_owner_fr = ark_ff::PrimeField::from_le_bytes_mod_order(&decode_hex32(
        &td_material.td_derived_owner_le_hex,
    )?);

    // The flat-aggregation prover wraps `noir_rs` which spins up its own
    // tokio runtime internally; calling it directly from this async
    // context tries to drop a runtime inside another runtime and
    // panics. Push the synchronous work onto a blocking thread.
    let bundle = {
        let su_inputs = su_inputs.clone();
        tokio::task::spawn_blocking(move || {
            pso_l2_client::wallet::prove_su_aggregation(&su_inputs, td_id, td_owner_fr)
        })
        .await
        .map_err(|e| eyre::eyre!("prove join: {e}"))??
    };
    tracing::info!(
        tier = ?bundle.tier,
        proof_bytes_len = bundle.proof_bytes_hex.len() / 2 - 1,
        "wallet produced flat aggregation proof"
    );

    // -----------------------------------------------------------------
    // 6. Submit the TributeDraft. The on-chain `_collectSuTotals`
    //    reconstructs `[owner_0, nft_hash_0, ..., owner_{N-1},
    //    nft_hash_{N-1}]` from canonical SU storage; the wallet's
    //    proof embeds the same 2N field elements as its public-input
    //    prefix, and the `zk_verify` precompile verifies the proof
    //    against `FLAT_AGGREGATION_N{tier_n}`'s canonical VK.
    // -----------------------------------------------------------------
    let tx = pso_l2_client::wallet::submit_tribute_draft(&sra_client, &bundle).await?;
    tracing::info!(?tx, "TributeDraft.submit succeeded");

    Ok(())
}

/// Decode a `0x`-prefixed hex string into a `[u8; 32]`.
fn decode_hex32(s: &str) -> eyre::Result<[u8; 32]> {
    let v = hex::decode(s.trim_start_matches("0x"))?;
    if v.len() != 32 {
        eyre::bail!("expected 32 bytes hex, got {}", v.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Parse a `0x`-prefixed 256-bit hex string into a `U256`.
fn parse_u256_hex(s: &str) -> eyre::Result<U256> {
    let bytes = decode_hex32(s)?;
    Ok(U256::from_be_bytes(bytes))
}
