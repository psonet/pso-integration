//! In-process SRA bridge.
//!
//! Models the production SRA mint pipeline as a background task. The
//! wallet (or, in the test suite, a scenario body) speaks to it via a
//! [`Bridge`] handle that forwards [`SuMintRequest`]s over an `mpsc`
//! channel and returns the typed receipt on a `oneshot`.
//!
//! For every request the loop:
//!
//! 1. Rolls a fresh `(sk_cu, pk_cu, su_nonce)` triple — the SRA's
//!    ephemeral per-SU material.
//! 2. Derives the App. A shared key from `(sk_cu, consent_pk, su_nonce)`,
//!    reinterprets the secp256k1 output as a Grumpkin scalar
//!    (HKDF output mod `q_Grumpkin`), and computes the matching
//!    `derivedOwner` Poseidon commitment.
//! 3. Calls `SpendingUnit.submit(...)` on the agents pool with that
//!    `derivedOwner` (BE-encoded — the on-chain side reads BE per
//!    the `0x0212` SU-hash precompile spec).
//! 4. Waits for the receipt, then replies with `(su_id, pk_cu,
//!    su_nonce, mint_tx)`.
//!
//! Shutdown semantics: the loop holds an `mpsc::Receiver` and the
//! [`Bridge`] holds the matching `Sender`. Dropping the `Bridge`
//! closes the channel; the loop sees `None` on its next poll and
//! exits cleanly. [`Bridge::shutdown`] is the explicit path that
//! awaits the join handle so the loop's `tracing` lines finish
//! draining before the test process exits.

use std::time::Duration;

use alloy::primitives::{FixedBytes, TxHash, U256};
use k256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::sync::{mpsc, oneshot};

use ark_bn254::Fr;
use ark_ff::PrimeField;

use pso_integrations_shared::witness::fr_to_be32;
use pso_l2_client::sra::MintSpendingUnitArgs;
use pso_sra_integration::generate_nft_ownership_with_nonce;

use crate::clients::sra::SraClient;

/// Inputs the caller supplies for a single SU mint.
#[derive(Debug, Clone)]
pub struct SuMintArgs {
    /// SU id (chosen by the caller — the bridge does not roll one;
    /// scenarios use [`crate::data::random_id`] when they want a
    /// fresh random id).
    pub su_id: U256,
    /// Wallet's long-lived consent public key. The bridge uses this
    /// to derive the same shared key the wallet will arrive at.
    pub consent_pk: PublicKey,
    /// ISO 4217 numeric currency code.
    pub currency: u16,
    /// Worldwide-day count (days since 2021-01-01).
    pub worldwide_day: u32,
    /// Settlement amount integer part.
    pub settlement_amount_base: u64,
    /// Settlement amount fractional part (atto).
    pub settlement_amount_atto: u128,
    /// SR ids consumed by this SU.
    pub sr_ids: Vec<U256>,
    /// AR ids (amendments) consumed.
    pub amendment_sr_ids: Vec<U256>,
}

/// Internal request carried over the mpsc channel.
pub struct SuMintRequest {
    pub args: SuMintArgs,
    /// Oneshot the loop writes the receipt back into.
    pub reply: oneshot::Sender<Result<SuMintReceipt, BridgeError>>,
}

/// Output the SRA hands back to the wallet after a successful mint.
#[derive(Debug, Clone)]
pub struct SuMintReceipt {
    /// Echo of the input id — handy for joins.
    pub su_id: U256,
    /// Per-SU ephemeral public key. The wallet feeds this back into
    /// `prepare_su_ownership_material` to reconstruct the same
    /// Grumpkin signing scalar.
    pub pk_cu: PublicKey,
    /// 32-byte per-SU nonce; same role as `pk_cu`.
    pub su_nonce: [u8; 32],
    /// Hash of the `SpendingUnit.submit` tx. Wait on it via
    /// `SraClient::wait_for_tx_success` before downstream calls if
    /// the test depends on `getData(su_id)` being live.
    pub mint_tx: TxHash,
}

/// Failure modes the bridge surfaces back.
#[derive(Debug)]
pub enum BridgeError {
    /// Crypto step failed (App. A reduction, Grumpkin derive,
    /// Poseidon ownership commit).
    Crypto(String),
    /// `SpendingUnit.submit` failed at the agents-pool / contract
    /// layer. The inner string is whatever
    /// `L2ClientError::Contract` surfaced — scenarios typically
    /// pump this through `decode_text` to assert a typed variant.
    Mint(String),
    /// Receipt poll timed out.
    Receipt(String),
    /// Bridge was shut down before the request was serviced.
    ChannelClosed,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::Crypto(s) => write!(f, "bridge crypto: {s}"),
            BridgeError::Mint(s) => write!(f, "bridge mint: {s}"),
            BridgeError::Receipt(s) => write!(f, "bridge receipt: {s}"),
            BridgeError::ChannelClosed => write!(f, "bridge channel closed"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// Handle to the background loop.
pub struct Bridge {
    /// Send channel — clone to enqueue from multiple callers.
    pub tx: mpsc::Sender<SuMintRequest>,
    handle: tokio::task::JoinHandle<()>,
}

impl Bridge {
    /// Submit one SU mint and await the receipt. Bundles the
    /// `oneshot` ceremony so scenarios don't have to.
    pub async fn mint_su(&self, args: SuMintArgs) -> Result<SuMintReceipt, BridgeError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(SuMintRequest { args, reply })
            .await
            .map_err(|_| BridgeError::ChannelClosed)?;
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(BridgeError::ChannelClosed),
        }
    }

    /// Explicit shutdown: drop the sender side and await the loop's
    /// join handle. Use this when the test wants the bridge's
    /// `tracing` output to flush before the process exits.
    pub async fn shutdown(self) {
        let Bridge { tx, handle } = self;
        drop(tx);
        let _ = handle.await;
    }
}

/// Spawn the SRA bridge loop. The returned [`Bridge`] is the only
/// handle into the background task; dropping it closes the mpsc
/// channel and lets the loop exit.
pub fn spawn_sra_loop(sra: SraClient) -> Bridge {
    let (tx, mut rx) = mpsc::channel::<SuMintRequest>(64);
    let handle = tokio::spawn(async move {
        tracing::debug!("SRA bridge loop started");
        while let Some(req) = rx.recv().await {
            let SuMintRequest { args, reply } = req;
            let res = handle_mint(&sra, args).await;
            // Reply may have been dropped if the caller went away
            // (cancelled future). That's not an error.
            let _ = reply.send(res);
        }
        tracing::debug!("SRA bridge loop exiting (channel closed)");
    });
    Bridge { tx, handle }
}

/// Run a single mint. Pulled out so the spawn closure stays small
/// and the crypto path is unit-testable in principle.
async fn handle_mint(sra: &SraClient, args: SuMintArgs) -> Result<SuMintReceipt, BridgeError> {
    tracing::debug!(su_id = %args.su_id, "bridge: handle_mint start");
    // ----- (1) Roll per-SU ephemeral material -----
    let mut sk_cu_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_cu_bytes);
    let sk_cu =
        SecretKey::from_slice(&sk_cu_bytes).map_err(|e| BridgeError::Crypto(e.to_string()))?;
    let pk_cu = sk_cu.public_key();

    let mut su_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut su_nonce);

    // ----- (2) derivedOwner via the SRA crate's public API -----
    //
    // The same `generate_nft_ownership_with_nonce` UniFFI-exported
    // function Kotlin/JVM SRA clients call. Routing the bridge
    // through it means the e2e suite exercises the public surface
    // real clients hit — any change to the App. A reduction, the
    // ECDH shape, or the Poseidon commitment is caught here without
    // the bridge needing its own parallel implementation.
    //
    // bb 5.x throws an uncatchable C++ exception that aborts the
    // process if invoked from the wrong tokio worker thread; push
    // the FFI work onto a blocking thread so the panic boundary is
    // in a sync frame the runtime can isolate.
    let consent_pk_bytes = args.consent_pk.to_sec1_bytes().to_vec();
    let sk_cu_vec = sk_cu_bytes.to_vec();
    let su_nonce_vec = su_nonce.to_vec();
    let ownership = tokio::task::spawn_blocking(move || {
        generate_nft_ownership_with_nonce(sk_cu_vec, consent_pk_bytes, su_nonce_vec)
    })
    .await
    .map_err(|e| BridgeError::Crypto(format!("ownership join: {e}")))?
    .map_err(|e| BridgeError::Crypto(format!("generate_nft_ownership: {e}")))?;

    // `generate_nft_ownership_with_nonce` returns the ownership Fr
    // as base58-encoded **little-endian** bytes (matching how the
    // SRA crate emits the value to its Kotlin caller). The on-chain
    // path needs BE — the `0x0212` SU-hash precompile parses BE and
    // the aggregation proof's public-input prefix copies BE verbatim.
    // Decode, re-interpret the LE bytes as Fr, and re-encode BE.
    let ownership_le_bytes = bs58::decode(&ownership.ownership)
        .into_vec()
        .map_err(|e| BridgeError::Crypto(format!("decode ownership bs58: {e}")))?;
    let ownership_le_arr: [u8; 32] = ownership_le_bytes.as_slice().try_into().map_err(|_| {
        BridgeError::Crypto(format!(
            "expected 32-byte ownership, got {}",
            ownership_le_bytes.len()
        ))
    })?;
    let owner_fr = Fr::from_le_bytes_mod_order(&ownership_le_arr);
    let derived_owner_bytes = fr_to_be32(&owner_fr);

    // ----- (3) On-chain mint via the agents pool -----
    let mint_args = MintSpendingUnitArgs {
        su_id: args.su_id,
        derived_owner: FixedBytes::from(derived_owner_bytes),
        settlement_currency: args.currency,
        worldwide_day: args.worldwide_day,
        settlement_amount_base: args.settlement_amount_base,
        settlement_amount_atto: args.settlement_amount_atto,
        sr_ids: args.sr_ids,
        amendment_sr_ids: args.amendment_sr_ids,
    };
    let mint_tx = sra
        .mint_spending_unit(mint_args)
        .await
        .map_err(|e| BridgeError::Mint(e.to_string()))?;

    // ----- (4) Wait for inclusion -----
    sra.wait_for_tx_success(mint_tx, Duration::from_secs(30))
        .await
        .map_err(|e| BridgeError::Receipt(e.to_string()))?;
    tracing::debug!(?mint_tx, "bridge: mint receipt success");

    // SRA "deletes" `sk_cu` — drop the binding (Rust frees it).
    drop(sk_cu);

    Ok(SuMintReceipt {
        su_id: args.su_id,
        pk_cu,
        su_nonce,
        mint_tx,
    })
}
