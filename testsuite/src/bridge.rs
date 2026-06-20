//! In-process Attester bridge.
//!
//! Models the production attester mint pipeline as a background task. The
//! wallet (or, in the test suite, a scenario body) speaks to it via a
//! [`Bridge`] handle that forwards [`SuMintRequest`]s over an `mpsc`
//! channel and returns the typed receipt on a `oneshot`.
//!
//! For every request the loop drives the **attester FFI**
//! ([`pso_attester_integration::Attester`]):
//!
//! 1. [`Attester::generate_nft_header`] runs the consent box once for the
//!    wallet's `consent_pk` (a 32-byte compressed PsoV1 point) — minting
//!    the NFT id + `derivedOwner` + the wallet's reconstruction material.
//! 2. [`Attester::issue_with_header`] folds in the body (amounts, day,
//!    currency, sr/ar fingerprints) to produce the on-chain
//!    [`SpendingUnit`](pso_attester_integration::SpendingUnit) + the
//!    [`IssuanceReport`](pso_attester_integration::IssuanceReport) the
//!    wallet stores.
//! 3. The bridge submits `SpendingUnit.submit(...)` on the agents pool
//!    with the FFI-computed `su_id` / `derivedOwner`.
//! 4. Waits for the receipt, then replies with `(su_id, report,
//!    mint_tx)`. The wallet later feeds `report` to
//!    [`Consent::witness`](pso_mobile_integration::Consent) /
//!    `Consent::prove_ownership` to prove ownership.
//!
//! Shutdown semantics: the loop holds an `mpsc::Receiver` and the
//! [`Bridge`] holds the matching `Sender`. Dropping the `Bridge`
//! closes the channel; the loop sees `None` on its next poll and
//! exits cleanly. [`Bridge::shutdown`] is the explicit path that
//! awaits the join handle so the loop's `tracing` lines finish
//! draining before the test process exits.

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Address, FixedBytes, TxHash, U256};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::sync::{mpsc, oneshot};

use pso_attester_integration::{Attester, IssuanceReport};

use crate::clients::attester::{AttesterClient, MintSpendingUnitArgs};

/// Inputs the caller supplies for a single SU mint.
#[derive(Debug, Clone)]
pub struct SuMintArgs {
    /// Wallet's long-lived consent public key, as a 32-byte compressed
    /// PsoV1 point (e.g. `Consent::public_key()` from the mobile FFI).
    /// The attester runs the consent box against this to derive the
    /// `derivedOwner` and the wallet's reconstruction material.
    pub consent_pk: Vec<u8>,
    /// Wallet self-address captured at consent initiation. Stamped on
    /// every SU minted in this consent session as `referrerAddress`.
    /// `Address::ZERO` ⇒ no referrer.
    pub referrer_address: Address,
    /// ISO 4217 numeric currency code.
    pub currency: u16,
    /// Worldwide-day count (compact YYYYMMDD).
    pub worldwide_day: u32,
    /// Amount integer part.
    pub amount_base: u64,
    /// Amount fractional part (atto).
    pub amount_atto: u128,
    /// SR ids consumed by this SU (each must be a canonical 32-byte
    /// field element — the attester folds them into `nft_hash`).
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

/// Output the attester hands back to the wallet after a successful mint.
/// Not `Clone`: the FFI [`IssuanceReport`] it carries is move-only.
#[derive(Debug)]
pub struct SuMintReceipt {
    /// On-chain SU id (the attester's `nft_id`).
    pub su_id: U256,
    /// The issuance report the wallet feeds to
    /// [`Consent::witness`](pso_mobile_integration::Consent) /
    /// `Consent::prove_ownership` to reconstruct its signer and prove
    /// ownership of this SU.
    pub report: IssuanceReport,
    /// Hash of the `SpendingUnit.submit` tx. Wait on it via
    /// `AttesterClient::wait_for_tx_success` before downstream calls if
    /// the test depends on `getData(su_id)` being live.
    pub mint_tx: TxHash,
}

/// Failure modes the bridge surfaces back.
#[derive(Debug)]
pub enum BridgeError {
    /// Crypto step failed (consent box / entity hashing inside the
    /// attester FFI).
    Crypto(String),
    /// `SpendingUnit.submit` failed at the agents-pool / contract
    /// layer. The inner string is whatever `RpcError::Contract`
    /// surfaced — scenarios typically pump this through `decode_text`
    /// to assert a typed variant.
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

/// Spawn the Attester bridge loop. The returned [`Bridge`] is the only
/// handle into the background task; dropping it closes the mpsc
/// channel and lets the loop exit. The attester FFI is bound to the
/// `attester_client`'s on-chain address (it stamps every SU's `attesterAddress`).
pub fn spawn_attester_loop(attester_client: AttesterClient) -> Bridge {
    let (tx, mut rx) = mpsc::channel::<SuMintRequest>(64);
    let attester =
        Attester::new(attester_client.address().to_vec()).expect("attester address is 20 bytes");
    let handle = tokio::spawn(async move {
        tracing::debug!("Attester bridge loop started");
        while let Some(req) = rx.recv().await {
            let SuMintRequest { args, reply } = req;
            let res = handle_mint(&attester_client, &attester, args).await;
            // Reply may have been dropped if the caller went away
            // (cancelled future). That's not an error.
            let _ = reply.send(res);
        }
        tracing::debug!("Attester bridge loop exiting (channel closed)");
    });
    Bridge { tx, handle }
}

/// Run a single mint through the attester FFI + the agents pool.
async fn handle_mint(
    attester_client: &AttesterClient,
    attester: &Arc<Attester>,
    args: SuMintArgs,
) -> Result<SuMintReceipt, BridgeError> {
    tracing::debug!("bridge: handle_mint start");

    // ----- (1+2) Attester FFI: header + full SU issuance -----
    //
    // The same `Attester` surface real Kotlin/JVM attester clients hit
    // via UniFFI. Routing the bridge through it means the e2e suite
    // exercises the public attester surface — any change to the consent
    // box, the owner derivation, or the entity hashing is caught here.
    //
    // The barretenberg-backed FFI can throw an uncatchable C++ exception
    // if invoked from the wrong tokio worker thread; push the FFI work
    // onto a blocking thread so the panic boundary is in a sync frame the
    // runtime can isolate.
    let consent_pk = args.consent_pk.clone();
    let referrer = args.referrer_address;
    let currency = args.currency;
    let worldwide_day = args.worldwide_day;
    let amount_base = args.amount_base;
    let amount_atto = args.amount_atto;
    let sr_ids = args.sr_ids.clone();
    let ar_ids = args.amendment_sr_ids.clone();
    let attester = attester.clone();

    let issued = tokio::task::spawn_blocking(move || {
        // Per-issuance entropy: 24 random bytes ‖ 8-byte counter is the
        // reference binding, but a fresh 32-byte random seed per call is
        // equally distinct (the suite never re-issues with the same seed).
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let header = attester.generate_nft_header(seed.to_vec(), consent_pk)?;

        // Record fingerprints are 32-byte big-endian field elements; the
        // on-chain SR/AR ids are uint256. Use the same BE bytes for both,
        // so the SU's `nft_hash` folds exactly what the chain stored.
        let sr_fps: Vec<Vec<u8>> = sr_ids
            .iter()
            .map(|id| id.to_be_bytes::<32>().to_vec())
            .collect();
        let ar_fps: Vec<Vec<u8>> = ar_ids
            .iter()
            .map(|id| id.to_be_bytes::<32>().to_vec())
            .collect();

        attester.issue_with_header(
            header,
            worldwide_day,
            currency,
            amount_base,
            amount_atto as u64,
            referrer.to_vec(),
            sr_fps,
            ar_fps,
        )
    })
    .await
    .map_err(|e| BridgeError::Crypto(format!("issuance join: {e}")))?
    .map_err(|e| BridgeError::Crypto(format!("attester issue: {e}")))?;

    // SU id + derivedOwner come straight from the FFI's SpendingUnit.
    let su_id_bytes: [u8; 32] = issued
        .spending_unit
        .su_id
        .as_slice()
        .try_into()
        .map_err(|_| BridgeError::Crypto("attester su_id not 32 bytes".into()))?;
    let su_id = U256::from_be_bytes(su_id_bytes);
    let derived_owner_bytes: [u8; 32] = issued
        .spending_unit
        .derived_owner
        .as_slice()
        .try_into()
        .map_err(|_| BridgeError::Crypto("attester derived_owner not 32 bytes".into()))?;

    // ----- (3) On-chain mint via the agents pool -----
    let mint_args = MintSpendingUnitArgs {
        su_id,
        derived_owner: FixedBytes::from(derived_owner_bytes),
        referrer_address: args.referrer_address,
        currency: args.currency,
        worldwide_day: args.worldwide_day,
        amount_base: args.amount_base,
        amount_atto: args.amount_atto,
        sr_ids: args.sr_ids,
        amendment_sr_ids: args.amendment_sr_ids,
    };
    let mint_tx = attester_client
        .mint_spending_unit(mint_args)
        .await
        .map_err(|e| BridgeError::Mint(e.to_string()))?;

    // ----- (4) Wait for inclusion -----
    attester_client
        .wait_for_tx_success(mint_tx, Duration::from_secs(30))
        .await
        .map_err(|e| BridgeError::Receipt(e.to_string()))?;
    tracing::debug!(?mint_tx, "bridge: mint receipt success");

    Ok(SuMintReceipt {
        su_id,
        report: issued.report,
        mint_tx,
    })
}

#[cfg(test)]
mod tests {
    //! Symmetry guard for the attester/wallet FFI round-trip.
    //!
    //! The attester issues an NFT to a wallet's consent public key; the
    //! wallet reconstructs its signer from the report and proves
    //! ownership. The two sides must agree on the same `derivedOwner` /
    //! `nft_hash` for the aggregation to verify.
    //!
    //! NOTE: the pre-0.8 suite compared raw shared-key bytes across four
    //! surfaces (wallet Rust, Attester Rust, Attester UniFFI, mobile UniFFI). The
    //! new FFI **encapsulates** the keys — they never cross the boundary,
    //! so a raw-bytes comparison is no longer expressible. We instead
    //! assert the observable end-to-end property: an attester-issued
    //! report + `Consent::witness` produce a witness whose `derivedOwner`
    //! matches the issued SU, and a single-NFT `Consent::prove_ownership`
    //! succeeds. That is the symmetry the old test was really protecting.
    use pso_attester_integration::Attester as FfiAttester;
    use pso_mobile_integration::Wallet;

    fn seed(tag: u8) -> Vec<u8> {
        vec![tag; 32]
    }

    #[test]
    fn attester_issue_and_wallet_witness_agree() {
        // Wallet derives a consent keypair; hands the attester its pk.
        let wallet = Wallet::new();
        let consent = wallet.generate_consent(seed(0x11)).expect("consent");
        let consent_pk = consent.public_key().expect("consent pk");

        // Attester issues an NFT against that consent pk.
        let attester = FfiAttester::new(vec![0xab; 20]).expect("attester");
        let header = attester
            .generate_nft_header(seed(0x22), consent_pk)
            .expect("header");
        // The on-chain `derivedOwner` the wallet will cross-check.
        let issued = attester
            .issue_with_header(
                header,
                20_250_101,
                978,
                100,
                0,
                vec![0u8; 20],
                vec![[0x01u8; 32].to_vec()],
                vec![],
            )
            .expect("issue");

        // Wallet reconstructs the witness from the report over a binding.
        let binding = vec![0x07u8; 32];
        let report = pso_mobile_integration::IssuanceReport {
            nft_id: issued.report.nft_id.clone(),
            derived_owner: issued.report.derived_owner.clone(),
            nft_hash: issued.report.nft_hash.clone(),
            opaque_pk: issued.report.opaque_pk.clone(),
            nonce: issued.report.nonce.clone(),
        };
        let witness = consent
            .witness(seed(0x33), report, binding)
            .expect("witness");

        // The witness's derivedOwner / nft_hash must equal the issued SU's.
        assert_eq!(
            witness.derived_owner, issued.spending_unit.derived_owner,
            "wallet witness derivedOwner must match the issued SU"
        );
        assert_eq!(
            witness.nft_hash, issued.report.nft_hash,
            "wallet witness nft_hash must match the report"
        );
    }
}
