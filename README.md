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
| L2 RPC client + ABI bindings               | shipped | `pso-l2-client` (alloy-based; inline `sol!` for the 4 predeployed contracts; SRA + Wallet flow functions) |
| SRA CLI (register SR/AR, mint SU)          | shipped | `pso-sra-cli` |
| Wallet CLI (prepare SU, aggregate, submit TD, prove TD full) | shipped | `pso-wallet-cli` |
| End-to-end test (programmatic, not via CLI) | shipped | `pso-l2-e2e-tests` — `#[ignore]` by default; opt in with `PSO_L2_RPC=… cargo test -p pso-l2-e2e-tests -- --ignored` |

The shipped surface today covers the full client lifecycle: wallet-side
ZK proof generation (ownership, aggregation, full proof), the MinRoot
VDF prover for Users-pool gating, and the alloy-based L2 RPC client +
two CLIs that the SRA registrar and wallet use to talk to the chain.
Each lives in this repo for the same reason — they all depend on k256
/ native crypto and would force `pso-protocol` to carry an EC
dependency if they lived there.

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
├── Cargo.toml                          # 9-member workspace
├── crates/
│   ├── pso-integrations-shared/        # Shared ECDH + KDF + the
│   │                                   # `witness` module: k256-aware
│   │                                   # witness builders that used to
│   │                                   # live in `pso-zk-core::witness`.
│   ├── pso-mobile-integration/         # UniFFI wrapper for React Native
│   │                                   # (iOS staticlib, Android cdylib).
│   │                                   # Hosts the ZK proof API + the
│   │                                   # MinRoot VDF FFI.
│   ├── pso-sra-integration/            # UniFFI bindings for the SRA
│   │                                   # registrar — secp256k1 ECDH +
│   │                                   # Poseidon5 ownership derivation.
│   ├── pso-l2-client/                  # Alloy-based L2 RPC client +
│   │                                   # inline `sol!` ABI bindings +
│   │                                   # SRA/Wallet flow functions.
│   └── pso-l2-e2e-tests/               # Integration test crate that
│                                       # exercises the full SRA + Wallet
│                                       # flow programmatically (no CLI
│                                       # invocation). #[ignore]'d by
│                                       # default; needs a running L2.
├── cli/
│   ├── pso-zk-cli/                     # ZK proof CLI (NFT gen, proof
│   │                                   # gen/verify, aggregate workflow).
│   ├── pso-sra-cli/                    # SRA-side L2 ops: register SR,
│   │                                   # register AR, mint SU.
│   └── pso-wallet-cli/                 # Wallet-side L2 ops: prepare SU,
│                                       # aggregate, submit TD, prove
│                                       # TD full proof.
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
- `alloy` (1.x umbrella) — L2 RPC client + ABI bindings + transaction submission.

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
