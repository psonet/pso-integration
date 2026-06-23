# pso-mobile-integration

UniFFI bindings for the PSO **wallet** — on-device ZK proving + the
proof-of-personhood VDF. Built on [`pso-protocol`](https://github.com/psonet/pso-protocol)
0.8, the [`pso-zk-canonical`](https://github.com/psonet/pso-zk-circuits) circuits,
and the `pso-zk-backend` barretenberg prover (real UltraHonkKeccak, on-device).
Ships as an **iOS staticlib + Android cdylib**.

## Object model

- **`Wallet`** — derives keys from a 32-byte entropy seed (held by the caller,
  passed per call), and aggregates ownership into a tribute-draft proof. The
  bindings are the **L2 side** (ownership/aggregation verify on L2); the
  `l2_chain_id` is a **wallet setting** feeding the VDF + the L2 aggregation
  binding. The **L1** full proof's binding takes its chain id per call.
  - `new(l2_chain_id)` — lazy SRS (cache / network). `new_with_srs(srs_path, l2_chain_id)`
    — construct with an **app-bundled SRS file** and pre-size the CRS to the full
    proof; the on-device path (mobile builds ship without the network SRS
    fallback, so the SRS *must* be provided this way — see [SRS](#srs)).
  - `compute_binding(sender_address, tribute_draft_id) -> bytes` — the **L2**
    submission binding (`Hash([DOMAIN, sender, id_lo, id_hi, l2_chain_id])`,
    `l2_chain_id` from the wallet) the aggregation proof commits to; feed the SAME
    value to each `witness`.
  - `generate_consent(seed) -> Consent` / `load_consent(secret) -> Consent`
  - `generate_nft_header(seed) -> NftHeader` — a tribute draft's own NFT key.
  - `prove_ownership(seed, sender_address, tribute_draft_id, witnesses) -> AggregationProofResult`
    — the **L2** aggregation proof over per-NFT `NftOwnershipWitness`es; the
    binding is computed internally from `sender_address` + `tribute_draft_id` +
    the wallet's `l2_chain_id` (witnesses must match it); picks the smallest
    fitting tier (1/2/4/8/16/32/64), pads, proves.
  - **Full proof** (the minted TD's **L1** proof = ownership ∥ Merkle inclusion):
    - `tribute_ownership_witness(nft_header, worldwide_day, currency, base, atto, su_ids, l1_sender_address, l1_chain_id) -> NftOwnershipWitness`
      — the TD's *own* ownership half: signed by the `nft_header` key over the
      **L1** binding (`binding(l1_sender, nft_header.id, l1_chain_id)`), `nft_hash`
      folded internally from the TD fields. (`tribute_draft_id == nft_header.id`.)
    - `prove_full(ownership: NftOwnershipWitness, inclusion: NftInclusionWitness) -> FullProofResult`
      — combines that with the inclusion half (the node's `pso_getInclusionPath`,
      a [`NftInclusionWitness`]); the circuit checks the path against
      `inclusion.merkle_root` (the node's root, used as-is — not recomputed).
  - MinRoot VDF (Users-pool gating): `derive_vdf_input(signer, nonce, submitted_block)`
    (uses the wallet's `l2_chain_id`), `compute_vdf(input, difficulty) -> VdfResult`
    (slow path — run off the UI thread), `verify_vdf(...)`, `is_vdf_block_valid(...)`,
    `vdf_constants()`.
- **`Consent`** — the wallet's long-lived consent keypair (the signing key stays
  encapsulated; never crosses the boundary).
  - `public_key()` (hand to an attester for issuance), `secret()` (persist).
  - `witness(seed, report, binding) -> NftOwnershipWitness` — reconstruct the
    signer from an attester `IssuanceReport` and build the aggregation slot.
  - `prove_ownership(seed, report, binding) -> ProofResult` — single-NFT proof.

Records (`IssuanceReport`, `NftHeader`, `NftOwnershipWitness` (its `pk` is an
`EmbeddedCurvePoint { x, y }`), `NftInclusionWitness`, `ProofResult`,
`AggregationProofResult`, `FullProofResult`, `VdfResult`, `VdfConstants`) carry
the data that crosses; field elements / points are 32-byte big-endian `bytes`.
Non-canonical field inputs are rejected.

`testsuite/src/scenarios/s001_happy_flow.rs` (in the workspace) is the reference
for how `Consent::witness` + `Wallet::prove_ownership` compose end-to-end against
a live chain.

## Flows

Inputs the caller supplies: `seed` (wallet entropy), `sender` (L2 submitter EOA),
`l1_sender` (L1 settlement EOA), and the per-SU body fields (`worldwide_day`,
`currency`, `base`, `atto`, `su_ids`) — these come from the attester-minted
SpendingUnits. Everything else is produced by the wallet.

**1 — Mint a TributeDraft (settles on L2).** The TD is itself an NFT, so the
wallet mints its header first; `nft_header.id` *is* the tribute-draft id, and
`nft_header.derived_owner` is the on-chain `derivedOwner`.

```
wallet     = Wallet::new_with_srs(srs_path, l2_chain_id)
consent    = wallet.generate_consent(seed)         // consent.public_key() → attester → IssuanceReport/SU
nft_header = wallet.generate_nft_header(seed)       // the TD's own key: .id = td id, .derived_owner, .nft_sk/.nonce
binding    = wallet.compute_binding(sender, nft_header.id)
witness[i] = consent.witness(seed, report[i], binding)              // per SU
agg        = wallet.prove_ownership(seed, sender, nft_header.id, witness[..])
  → L2:  TributeDraft.submit(id = nft_header.id, derivedOwner = nft_header.derived_owner, suIds = su_ids, proof = agg)
  → chain emits LeafInserted(treeId, leafIndex, leaf)
```

**2 — Full proof for the minted TD (settles on L1).** Reuse the SAME
`nft_header` + TD body fields. L1 needs the **signed tree root**. The committee
doesn't sign the root directly — `pso_getFinalizeCert` is a threshold signature
over the block's consensus digest `tipDigest = SHA256(contextEncoded ‖ parent ‖
height ‖ timestampMs ‖ payloadHash ‖ r)`, where the header field `r` **is** the
IMT root the block anchors. So the signature commits to the root transitively;
the cert preimage carries `r` + `contextEncoded` so a verifier can rebuild the
digest and check `r` is inside it. The wallet only produces the ZK proof; the
cert is a node artifact the app fetches and forwards.

```
incl = NftInclusionWitness ← node  pso_getInclusionPath(treeId, leafIndex)   // { root, siblings[32], leafIndex, blockNumber }
cert = node  pso_getFinalizeCert(incl.blockNumber)                           // committee threshold sig over tipDigest (which folds r)
own  = wallet.tribute_ownership_witness(nft_header, worldwide_day, currency, base, atto, su_ids, l1_sender, l1_chain_id)
full = wallet.prove_full(own, incl)
  → L1 verifies, for the SAME finalized block:
       (a) the full proof against `incl.root` (= the circuit's expected_merkle_root)
       (b) the threshold sig over `tipDigest`
       (c) recompute `tipDigest` from the cert preimage (incl. `r`) → binds `r`
       (d) `r == incl.root`  — the attested root == the proof's root (mismatch ⇒ reject)
```

## Build

```bash
cargo build -p pso-mobile-integration
cargo test  -p pso-mobile-integration
```

Links C++ barretenberg (via `pso-zk-backend`), so it needs a C++ toolchain
(cmake/clang) + network access (noir git deps + first-run SRS).

**Mobile slices** (release CI) are built with the max-optimization `mobile`
profile (`opt-level = 3`, fat LTO, `codegen-units = 1`, `strip`) — proving runs
on-device. The profile keeps the default `unwind` (not `panic = "abort"`) so
UniFFI's `catch_unwind` can turn a Rust panic into a catchable binding-side
error instead of aborting the host app.

- **iOS** — `aarch64-apple-ios` (+ sim) staticlib.
- **Android** — `aarch64-linux-android` + `x86_64-linux-android` cdylib via
  `cargo-ndk`. barretenberg is **built from source against the Android NDK** (not
  the upstream prebuilt) so the lib links the NDK libc++ (`std::__ndk1::`) and
  loads cleanly against `libc++_shared.so` on device.

A failed cross-build on any slice blocks the entire release (the `github-release`
job requires every build job to succeed) — releases are all-or-nothing.

The mobile slices are built **`--no-default-features`**, which drops the SRS
network fallback (`reqwest` + its tokio runtime) entirely — see [SRS](#srs).

Generate the foreign bindings (Kotlin / Swift) with `uniffi-bindgen-mobile`.

## SRS

Proving needs the BN254 G1 trusted setup (the "SRS"/CRS). An on-device prover
must **never** fetch it at proving time, so the mobile slices are built with
`--no-default-features`: this drops `pso-zk-backend`'s `with-network-srs`
feature (and `reqwest`/tokio with it), and a missing SRS becomes a clear error
instead of a (panicking) `reqwest::blocking` download.

The app therefore **ships the SRS as a bundled asset** and hands its path to
`Wallet::new_with_srs(srs_path, chain_id)` once at startup. The CRS is pre-sized to the
full proof — the largest aggregation tier (n64, `(1<<20)+1` points, ~64 MiB) —
so any tribute up to the protocol max proves; the bytes are integrity-checked
against a pinned hash before use. Desktop/CI builds (default features) keep the
network fallback and can use the lazy `Wallet::new()`.

## License

[MIT](../../LICENSE)
