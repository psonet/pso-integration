# pso-integration

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Client-side integration layer** for the PSO L2 — everything a wallet,
SRA registrar, or other off-chain client needs to participate in the
network. Bridges the consensus-binding primitives in
[`pso-protocol`](../pso-protocol) and the Noir prover in
[`pso-zk-circuits`](../pso-zk-circuits) into UniFFI bindings, a CLI,
and shared cryptographic helpers.

One of four sibling repos in the post-extraction layout:

- [`pso-protocol`](../pso-protocol) — consensus-binding hash primitives
  and witness types.
- [`pso-zk-circuits`](../pso-zk-circuits) — Noir circuits + FFI prover.
- **`pso-integration`** *(this repo)* — UniFFI wrappers, CLI, NFT
  domain types, k256-bound witness builders, VDF FFI (planned), and
  the L2-interaction surface that mobile / SRA clients consume.
- [`pso-chain`](../pso-chain) — PSO L2 chain.

Absorbs the wallet/CLI/FFI half of the legacy `pso-zk-proof`
workspace. The Noir circuits and FFI prover live in `pso-zk-circuits`.

## Scope

The integration layer is intentionally broad — it owns every off-chain
interaction a client makes with the L2:

| Concern                                    | Status  | Lives in                            |
| ------------------------------------------ | ------- | ----------------------------------- |
| Wallet keypair derivation (ECDH + KDF)     | shipped | `pso-integrations-shared`           |
| Poseidon5 ownership commitment (k256 side) | shipped | `pso-integrations-shared::witness`  |
| ZK witness construction (single / full / aggregation) | shipped | `pso-integrations-shared::witness`  |
| TributeDraft / SpendingUnit struct types   | shipped | `domain/pso-nft`                    |
| Mobile UniFFI bindings (iOS / Android)     | shipped | `pso-mobile-integration`            |
| SRA registrar UniFFI bindings              | shipped | `pso-sra-integration`               |
| Command-line frontend                      | shipped | `cli/pso-zk-cli`                    |
| VDF FFI binding (proof-of-personhood)      | shipped | `pso-mobile-integration::vdf` (`compute_vdf`, `verify_vdf`, `derive_vdf_input`, `vdf_constants`) — see `pso-vdf` crate |
| L2 RPC client (submit TD, read state)      | planned | new crate — alloy-based, not yet started |

The shipped surface today is wallet-side ZK proof generation, the
shared cryptographic primitives, and the MinRoot VDF prover. The L2
RPC client lands here next; alongside ZK and VDF it belongs in this
repo for the same reason — they all depend on k256 / native crypto
and would force `pso-protocol` to carry an EC dependency if they
lived there.

## Why split it out

Wallet release cadence is the fastest of the three layers — bug fixes
and UX changes ship without recompiling circuits or redeploying chain
code. Keeping integration code in its own repo means:

- Mobile / desktop builds don't trigger a Noir / C++ recompile.
- The `pso-protocol` and `pso-zk-circuits` consumers can hold a wallet
  release at a known-good pin while integration iterates.
- The k256 / UniFFI / alloy dependency tree stays out of
  `pso-protocol` (which must not pull in elliptic-curve crypto — every
  chain precompile that delegates to `pso-protocol` would inherit it
  otherwise).

## Layout

```
pso-integration/
├── Cargo.toml                          # 5-member workspace
├── crates/
│   ├── pso-integrations-shared/        # Shared ECDH + KDF + the
│   │                                   # NEW `witness` module: k256-aware
│   │                                   # witness builders that used to
│   │                                   # live in `pso-zk-core::witness`.
│   ├── pso-mobile-integration/         # UniFFI wrapper for React Native,
│   │                                   # iOS staticlib, Android cdylib.
│   │                                   # Wallet-facing API; will host the
│   │                                   # VDF prover FFI once it lands.
│   └── pso-sra-integration/            # UniFFI bindings for the SRA
│                                       # registrar — secp256k1 ECDH +
│                                       # Poseidon5 ownership derivation.
├── cli/
│   └── pso-zk-cli/                     # Command-line frontend for
│                                       # NFT generation, proof gen/verify,
│                                       # the aggregate workflow, and
│                                       # whatever L2-interaction commands
│                                       # land alongside the RPC client.
└── domain/
    └── pso-nft/                        # TributeDraft + SpendingUnit
                                        # struct types and trait impls.
                                        # All hash formulas now delegate
                                        # to `pso_protocol::nft::*` — the
                                        # struct types stay for backward
                                        # compatibility while consumers
                                        # migrate to ABI-type impls.
```

## Dependencies

- [`pso-protocol`](../pso-protocol) — path-pinned. Source of every hash
  formula and witness data type.
- [`pso-zk-circuits`](../pso-zk-circuits) — path-pinned. Provides the
  Noir prover and canonical descriptors.
- `k256` — secp256k1 keypair operations, ECDSA prehash signing,
  SEC1 coordinate extraction.
- `uniffi` — mobile / SRA FFI bindings.
- `clap`, `tabled` — CLI surface.
- `pso-vdf` — MinRoot VDF prover (Users-pool tx gating).
- *(planned)* `alloy` — L2 RPC client + transaction submission.

## Build

```bash
cargo build --workspace
cargo test  --workspace                              # all tests
cargo test  -p pso-nft                               # NFT trait impls
cargo test  -p pso-integrations-shared --all-features
```

For mobile builds:

```bash
# iOS staticlib
cargo build --profile mobile --target aarch64-apple-ios -p pso-mobile-integration

# Android cdylib
cargo ndk -t arm64-v8a build --profile mobile -p pso-mobile-integration
```

UniFFI bindings are generated by the `uniffi-bindgen-mobile` /
`uniffi-bindgen-sra` binaries — see each crate's README.

## Witness builders

`pso-integrations-shared::witness` is the production home of the
k256-bound witness builders that used to live in `pso-zk-core::witness`:

```rust
use pso_integrations_shared::witness::{
    build_full_proof_witness, FullProofWitnessCtx,
    ownership_from_secret_key, generate_aggregation_witness,
    AggregationWitnessCtx,
};

let witness = build_full_proof_witness(
    &nft,
    FullProofWitnessCtx {
        secret_key: &sk,
        nonce,
        merkle_path: &merkle_path,
    },
)?;
```

The builders are free functions rather than blanket `GenerateWitness<Ctx>`
trait impls because Rust's orphan rule blocks the latter — both the
trait (`pso_protocol::witness::GenerateWitness`) and the receiver type
`T` are foreign to this crate. The byte layout is identical to the old
trait-method version.

## License

[MIT](LICENSE) — same as `pso-protocol` / `pso-zk-circuits` / `pso-vdf`.
