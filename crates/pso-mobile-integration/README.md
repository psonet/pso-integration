# pso-mobile-integration

UniFFI bindings for the PSO **wallet** — on-device ZK proving + the
proof-of-personhood VDF. Built on [`pso-protocol`](https://github.com/psonet/pso-protocol)
0.8, the [`pso-zk-canonical`](https://github.com/psonet/pso-zk-circuits) circuits,
and the `pso-zk-backend` barretenberg prover (real UltraHonkKeccak, on-device).
Ships as an **iOS staticlib + Android cdylib**.

## Object model

- **`Wallet`** — derives keys from a 32-byte entropy seed (held by the caller,
  passed per call), and aggregates ownership into a tribute-draft proof.
  - `generate_consent(seed) -> Consent` / `load_consent(secret) -> Consent`
  - `generate_nft_header(seed) -> NftHeader` — a tribute draft's own NFT key.
  - `prove_ownership(seed, binding, witnesses) -> AggregationProofResult` —
    aggregate per-NFT `NftOwnershipWitness`es over the shared submission binding;
    picks the smallest fitting tier (1/2/4/8/16/32/64), pads, proves.
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

**Mobile slices** (release CI):

- **iOS** — `aarch64-apple-ios` (+ sim) staticlib.
- **Android** — `aarch64-linux-android` + `x86_64-linux-android` cdylib via
  `cargo-ndk`. barretenberg is **built from source against the Android NDK** (not
  the upstream prebuilt) so the lib links the NDK libc++ (`std::__ndk1::`) and
  loads cleanly against `libc++_shared.so` on device.

Generate the foreign bindings (Kotlin / Swift) with `uniffi-bindgen-mobile`.

## License

[MIT](../../LICENSE)
