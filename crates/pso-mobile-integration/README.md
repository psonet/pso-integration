# pso-mobile-integration

UniFFI bindings for the PSO **wallet** — on-device ZK proving + the
proof-of-personhood VDF. Built on [`pso-protocol`](https://github.com/psonet/pso-protocol)
0.8, the [`pso-zk-canonical`](https://github.com/psonet/pso-zk-circuits) circuits,
and the `pso-zk-backend` barretenberg prover (real UltraHonkKeccak, on-device).
Ships as an **iOS staticlib + Android cdylib**.

## Object model

- **`Wallet`** — derives keys from a 32-byte entropy seed (held by the caller,
  passed per call), and aggregates ownership into a tribute-draft proof.
    The `chain_id` is a **wallet setting** (folded into every binding).
  - `new(chain_id)` — lazy SRS (cache / network). `new_with_srs(srs_path, chain_id)`
    — construct with an **app-bundled SRS file** and pre-size the CRS to the full
    proof; the on-device path (mobile builds ship without the network SRS
    fallback, so the SRS *must* be provided this way — see [SRS](#srs)).
  - `compute_binding(sender_address, tribute_draft_id) -> bytes` — the submission
    binding (`Hash([DOMAIN, sender, id_lo, id_hi, chain_id])`, `chain_id` from the
    wallet) the proof commits to; feed the SAME value to each `witness`.
  - `generate_consent(seed) -> Consent` / `load_consent(secret) -> Consent`
  - `generate_nft_header(seed) -> NftHeader` — a tribute draft's own NFT key.
  - `prove_ownership(seed, sender_address, tribute_draft_id, witnesses) -> AggregationProofResult`
    — aggregate per-NFT `NftOwnershipWitness`es; the binding is computed
    internally from `sender_address` + `tribute_draft_id` + the wallet's
    `chain_id` (witnesses must match it); picks the smallest fitting tier
    (1/2/4/8/16/32/64), pads, proves.
  - MinRoot VDF (Users-pool gating): `derive_vdf_input(signer, nonce, submitted_block, chain_id)`,
    `compute_vdf(input, difficulty) -> VdfResult` (slow path — run off the UI
    thread), `verify_vdf(...)`, `is_vdf_block_valid(...)`, `vdf_constants()`.
- **`Consent`** — the wallet's long-lived consent keypair (the signing key stays
  encapsulated; never crosses the boundary).
  - `public_key()` (hand to an attester for issuance), `secret()` (persist).
  - `witness(seed, report, binding) -> NftOwnershipWitness` — reconstruct the
    signer from an attester `IssuanceReport` and build the aggregation slot.
  - `prove_ownership(seed, report, binding) -> ProofResult` — single-NFT proof.

Records (`IssuanceReport`, `NftHeader`, `NftOwnershipWitness`, `ProofResult`,
`AggregationProofResult`, `VdfResult`, `VdfConstants`) carry the data that
crosses; field elements / points are 32-byte big-endian `bytes`. Non-canonical
field inputs are rejected.

`testsuite/src/scenarios/s001_happy_flow.rs` (in the workspace) is the reference
for how `Consent::witness` + `Wallet::prove_ownership` compose end-to-end against
a live chain.

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
