# pso-integration

[![CI](https://github.com/psonet/pso-integration/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/psonet/pso-integration/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/psonet/pso-integration?display_name=tag&sort=semver)](https://github.com/psonet/pso-integration/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Client-side integration layer** for the PSO L2 — everything a wallet,
SRA registrar, or e2e harness needs to participate in the network.
Bridges the consensus-binding primitives in
[`pso-protocol`](https://github.com/psonet/pso-protocol) and the Noir
prover in [`pso-zk-circuits`](https://github.com/psonet/pso-zk-circuits)
into UniFFI bindings, two CLIs, the typed L2 RPC client, and the
`pso-e2e` end-to-end test suite that pso-chain CI runs against every
PR.

One of four sibling repos in the PSO multi-repo layout:

- [`pso-protocol`](https://github.com/psonet/pso-protocol) — consensus-binding hash primitives and witness types.
- [`pso-zk-circuits`](https://github.com/psonet/pso-zk-circuits) — Noir circuits + FFI prover.
- **`pso-integration`** *(this repo)* — UniFFI wrappers, CLIs, NFT domain types, Grumpkin-Schnorr witness builders, MinRoot VDF FFI, the L2 RPC client, and `pso-e2e`.
- [`pso-chain`](https://github.com/psonet/pso-chain) — the L2 itself.

## Scope

Today's shipped surface covers the **full client lifecycle**: wallet-side
ZK proof generation (ownership / aggregation / full proof on
Grumpkin-Schnorr), the MinRoot VDF prover for Users-pool gating, the
alloy-based L2 RPC client + two CLIs, the typed `PsoContractError`
decoder a client uses to match contract reverts by selector, and the
scenario-driven `pso-e2e` harness pso-chain CI runs against every PR.

| Concern                                                       | Lives in                                              |
| ------------------------------------------------------------- | ----------------------------------------------------- |
| Wallet keypair derivation (secp256k1 ECDH + HMAC-SHA256 KDF)  | `pso-integrations-shared`                             |
| Poseidon ownership commitment (Grumpkin)                      | `pso-integrations-shared::witness`                    |
| Grumpkin-Schnorr sign + verify primitives                     | `pso-mobile-integration::schnorr` (`schnorr_sign_grumpkin`, `schnorr_verify_grumpkin`) |
| ZK witness construction (single / full / flat aggregation)    | `pso-integrations-shared::witness`                    |
| Flat-aggregation tier dispatch (N ∈ {1,2,4,8,16,32,64})       | `pso-zk-canonical::select_aggregation_tier`           |
| TributeDraft / SpendingUnit struct types                      | `domain/pso-nft`                                      |
| Mobile UniFFI bindings (iOS / Android)                        | `pso-mobile-integration` — prove, verify, VDF, keypair |
| SRA registrar UniFFI bindings                                 | `pso-sra-integration`                                 |
| Command-line frontends                                        | `cli/pso-sra-cli`, `cli/pso-wallet-cli`, `cli/pso-zk-cli` |
| L2 RPC client + ABI bindings                                  | `pso-l2-client` (alloy + inline `sol!` for the 4 predeploys + SRA/Wallet flow functions) |
| Typed contract-error decoder                                  | `pso-l2-client::contract_errors::PsoContractError`    |
| MinRoot VDF FFI (compute + verify + binding)                  | `pso-mobile-integration::vdf`                         |
| End-to-end test harness                                       | `testsuite/` — the `pso-e2e` binary; see [`testsuite/README.md`](testsuite/README.md) |

## Why this repo exists

Wallet release cadence is the fastest of the three layers — bug fixes
and UX changes ship without recompiling circuits or redeploying chain
code. Splitting integration code out of the chain repo means:

- Mobile / desktop builds don't trigger a Noir or C++ recompile.
- `pso-protocol` and `pso-zk-circuits` consumers can hold a wallet
  release at a known-good pin while this repo iterates.
- The k256 / UniFFI / alloy dependency tree stays out of
  `pso-protocol`, which must not pull in elliptic-curve crypto — every
  chain precompile that delegates to `pso-protocol` would inherit it
  otherwise.

## Layout

```
pso-integration/
├── Cargo.toml                              # 9-member workspace
├── crates/
│   ├── pso-integrations-shared/            # ECDH + KDF + the `witness`
│   │                                       # module (Grumpkin-Schnorr
│   │                                       # witness builders).
│   ├── pso-mobile-integration/             # UniFFI wrapper for React
│   │                                       # Native (iOS staticlib,
│   │                                       # Android cdylib). Hosts the
│   │                                       # ZK proof API, the VDF
│   │                                       # FFI, and the standalone
│   │                                       # `schnorr_sign_grumpkin` /
│   │                                       # `schnorr_verify_grumpkin`.
│   ├── pso-sra-integration/                # UniFFI bindings for the
│   │                                       # SRA registrar.
│   └── pso-l2-client/                      # Alloy-based L2 RPC client
│                                           # + inline `sol!` ABI +
│                                           # SRA/Wallet flow functions
│                                           # + typed contract-error
│                                           # decoder.
├── cli/
│   ├── pso-zk-cli/                         # ZK proof CLI (NFT gen,
│   │                                       # proof gen/verify, aggregate
│   │                                       # workflow).
│   ├── pso-sra-cli/                        # SRA-side L2 ops: register
│   │                                       # SR, register AR, mint SU.
│   └── pso-wallet-cli/                     # Wallet-side L2 ops: prepare
│                                           # SU material, aggregate,
│                                           # submit TD, prove TD
│                                           # ownership for L1 redemption.
├── domain/
│   └── pso-nft/                            # TributeDraft + SpendingUnit
│                                           # struct types. Hash formulas
│                                           # delegate to
│                                           # `pso_protocol::nft::*`.
└── testsuite/                              # `pso-e2e` scenario harness.
                                            # 35+ scenarios; see
                                            # testsuite/README.md.
```

## How to use

### Local verification (before pushing)

CI burns paid minutes; reproduce the relevant gate locally first.
Each command below maps to a CI step:

```bash
# Format & check (mirrors .github/actions/rust-check)
cargo fmt --all -- --check
cargo check --workspace --tests

# Unit & framework tests (mirrors .github/actions/rust-test)
cargo test --workspace --lib --tests

# Build the release binary (mirrors .github/actions/build-binaries)
cargo build --release -p pso-e2e-testsuite --bin pso-e2e

# Build the runtime image (mirrors .github/actions/publish-image)
mkdir -p dist && cp target/release/pso-e2e dist/
docker build -t pso-e2e:dev -f testsuite/Dockerfile .

# Preview what cog would bump (cocogitto must be installed locally:
#   cargo install --locked cocogitto).
cog bump --auto --dry-run

# Force a specific bump locally (push triggers the release path
# via the `push: tags` trigger — see "Triggering a release" below).
cog bump --auto
git push --follow-tags
```

`act` (https://github.com/nektos/act) runs the whole workflow
locally in a Docker container; it's a heavier setup but reproduces
the GHA environment more faithfully:

```bash
act push -W .github/workflows/ci.yml
```

### Triggering a release

The CI pipeline has four entry points:

| Trigger                                    | What runs                                                                  |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| `push: branches: [main]`                   | check + unit + image + tag (cog auto-bump). If cog bumped, release-* too.  |
| `pull_request`                             | check + unit only.                                                         |
| `push: tags: ["v*"]`                       | release-* only — re-build a tag's artifacts without re-bumping.            |
| `workflow_dispatch` (`tag` input optional) | With `tag`: same as push:tags. Without: same as push:main.                 |

Three practical patterns:

```bash
# A. Normal main flow: just commit + push, cog decides whether to
#    bump. Use conventional-commit prefixes (`feat:`, `fix:`,
#    `feat!:` for breaking) so cog actually picks them up.
git commit -m "feat(testsuite): add S038 …"
git push origin main

# B. Manual tag push: produce a tag locally and push it. The
#    release-* jobs fire on the `push: tags` trigger.
git tag v0.2.0
git push origin v0.2.0

# C. UI / scripted dispatch: trigger the release for an existing
#    tag without pushing anything.
gh workflow run ci.yml --field tag=v0.2.0
```

`gh workflow run ci.yml` with `tag=""` (or omitted) acts as a
manual re-run of the regular main pipeline.

### Build

```bash
# Whole workspace.
cargo build --workspace

# Network-free tests (cargo unit + framework).
cargo test --workspace --lib --tests

# Build just the e2e binary.
cargo build --release -p pso-e2e-testsuite --bin pso-e2e
```

Mobile builds:

```bash
# iOS staticlib.
cargo build --profile mobile --target aarch64-apple-ios \
            -p pso-mobile-integration

# Android cdylib.
cargo ndk -t arm64-v8a build --profile mobile \
            -p pso-mobile-integration
```

UniFFI bindings are emitted by each crate's `uniffi-bindgen-mobile` /
`uniffi-bindgen-sra` binary — see the per-crate READMEs.

### Run `pso-e2e` against a local devnet

`pso-e2e` is the scenario-driven harness. It connects to a running
`pso-chain --dev` instance, bootstraps the SRA registry, and walks
through every scenario in `testsuite/src/scenarios/` — both the
happy-path SR → AR → SU → TD round-trip and the 30+ negative-path
invariants the protocol enforces (envelope tampering, foreign-SRA
record references, malformed aggregation proofs, registry guards,
SRA lifecycle transitions, …).

```bash
# 1. Start pso-chain --dev in a separate shell.
pso-chain --dev

# 2. Run the suite (Hardhat keys are devnet defaults).
pso-e2e \
  --rpc-url       http://127.0.0.1:19545 \
  --actor-rpc-url http://127.0.0.1:8546  \
  --chain-id      19280501               \
  --admin-key     0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --sra-key       0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

# 3. Filter to a single scenario / family while iterating.
pso-e2e --admin-key … --sra-key … --only S001 -vv
pso-e2e --admin-key … --sra-key … --only S013,S014,S015,S016,S017,S031   # envelope/VDF tampering
pso-e2e --admin-key … --sra-key … --only S033,S035,S036,S037              # SRA admin lifecycle
pso-e2e --list                                                              # enumerate the suite without touching the chain
```

### Pre-built image

Every push to `main` publishes `ghcr.io/psonet/pso-e2e:main`; every
release tag publishes `:vX.Y.Z` + `:latest`. pso-chain CI consumes
the image directly:

```bash
docker pull ghcr.io/psonet/pso-e2e:main

docker run --rm --network host ghcr.io/psonet/pso-e2e:main \
  --rpc-url       http://127.0.0.1:19545 \
  --actor-rpc-url http://127.0.0.1:8546  \
  --chain-id      19280501               \
  --admin-key     "$ADMIN_KEY" \
  --sra-key       "$SRA_KEY"
```

### Scenario surface

`pso-e2e --list` prints the live count + ids. Grouped by what
they exercise:

| Group        | Range           | What                                                                           |
| ------------ | --------------- | ------------------------------------------------------------------------------ |
| Happy path   | S001            | Full SR → AR → SU mint via bridge → wallet TD prove + submit; `derivedOwner` round-trip. |
| Pool routing | S002 – S006     | Each pool admits only the txs it should: TD never on agents pool, SR/AR/SU never on actor pool without SRA registration. |
| SBT guards   | S007, S008      | Duplicate SR id → `AlreadyExists`; SR id 0 → `InvalidTokenId`.                 |
| SU validity  | S009 – S011, S020 | Foreign-SRA SR/AR + never-registered SR + double-spend → `SpendingRecordsNotOwnedBySender` / `SpendingRecordsAlreadyExist`. |
| TD invariants| S012, S021 – S023 | Empty `suIds`, `NotFound`, `NotSameWorldwideDay`, `NotSameCurrency`. |
| Envelope tampering | S013 – S017, S031 | Magic prefix, nullifier replay, stale `submitted_block`, bit-flipped VDF proof, bit-flipped VDF output, wrong VDF iteration count `T`. |
| Aggregation negatives | S018, S019 | `MalformedAggregationProof` (length) + `InvalidAggregationProof` (public-input mismatch). |
| Contract guards | S025 – S030 | `InvalidMetadata`, `InvalidAmount`, `NotAdmin`, `ZeroAddress`, `InvalidMask`, `SRANotActive`. |
| SRA lifecycle | S033, S035 – S037 | Revoke → SR.submit reverts `SRANotActive`; `updateMask` / `setRotationCandidate` round-trip; revoke unknown → `NotRegistered`. |

The full table with descriptions lives in
[`testsuite/README.md`](testsuite/README.md); each scenario file is
named after the invariant it asserts and carries a module-level
doc-comment explaining the chain-side guard it exercises.

### FFI surfaces for non-Rust clients

A React Native / iOS / Android client links against
`pso-mobile-integration` (UniFFI). The exported surface includes:

- **`derive_nft_keypair(consent_sk, sra_pk, nft_nonce)`** — App-A
  ECDH + HKDF → Grumpkin keypair.
- **`schnorr_sign_grumpkin(secret_key, message)`** /
  **`schnorr_verify_grumpkin(public_key, message, signature)`** —
  raw primitives for clients constructing their own witness.
- **`prove_spending_unit_ownership` / `prove_tribute_ownership` /
  `prove_spending_unit_full` / `prove_tribute_full` /
  `prove_su_ownership_aggregation`** — the canonical proof
  generators.
- **`compute_vdf` / `verify_vdf` / `derive_vdf_input` /
  `vdf_constants`** — MinRoot VDF FFI for Users-pool gating.

`testsuite/src/scenarios/s001_happy_flow.rs` is the reference for
how these primitives compose end-to-end against a live chain.

## CI

`ci.yml` is a single linear pipeline:

```
check ─┐
unit  ─┴─> image (push:main) ─> tag (cocogitto) ─> release-binaries ─> release-image ─> github-release
```

- `check + unit` run on every PR and push.
- `image` builds + pushes `ghcr.io/psonet/pso-e2e:main` on every
  successful main push.
- `tag` runs `cog bump --auto`; if a `feat:`/`fix:`/breaking commit
  landed since the last tag, the four release jobs fire and produce
  per-platform binaries (`pso-e2e-linux-x86_64-vX.Y.Z`,
  `pso-e2e-linux-aarch64-vX.Y.Z` — every released artifact carries the
  `-vX.Y.Z` version suffix) plus a versioned `:vX.Y.Z` + `:latest`
  image, the `pso-sra-integration-kotlin` JAR published to GitHub
  Packages Maven, and a GitHub release.
- `chore:` / `ci:` / `docs:` etc. commits are no-ops for cog — the
  release jobs short-circuit cleanly via
  `if: needs.tag.outputs.tag != ''`.

`pso-chain` consumes `ghcr.io/psonet/pso-e2e:main` directly in its
own CI (see [pso-chain `.github/workflows/ci.yml::e2e`](https://github.com/psonet/pso-chain/blob/main/.github/workflows/ci.yml)).

## Dependencies

- [`pso-protocol`](https://github.com/psonet/pso-protocol) — public; source of every hash formula + witness data type.
- [`pso-zk-circuits`](https://github.com/psonet/pso-zk-circuits) — private; provides the Noir prover and canonical descriptors.
- `barretenberg-rs` (5.x) — Grumpkin-Schnorr FFI backend.
- `noir_rs` — Noir/Barretenberg proving for the flat-aggregation tiers.
- `alloy` (1.x) — L2 RPC client + ABI bindings.
- `uniffi` — mobile / SRA FFI bindings.
- `pso-vdf` — MinRoot VDF prover.
- `clap` — CLI surface.

## Verifying releases

Releases tagged from `v0.3.7` onward ship sigstore cosign signatures + SLSA build-provenance attestations for every artifact: the e2e binaries, the mobile slices (best-effort matrix), the bindgen binaries, the `pso-sra-integration-kotlin.jar`, and `SHA256SUMS`. The JAR is signed as the unit; its bundled native libs are verified transitively via the JAR's SHA-256.

See [SECURITY.md](SECURITY.md) for the threat model, the matrix-aware semantics, and the full verify recipe.

Quick check (JAR):

```sh
TAG=v0.3.7
ARTIFACT="pso-sra-integration-kotlin-$TAG.jar"  # released filenames carry the -$TAG suffix
gh release download "$TAG" --repo psonet/pso-integration \
  --pattern "$ARTIFACT" --pattern "$ARTIFACT.sig" --pattern "$ARTIFACT.pem"
cosign verify-blob \
  --certificate "$ARTIFACT.pem" --signature "$ARTIFACT.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/psonet/pso-integration/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARTIFACT"
```

## License

[MIT](LICENSE) — same as `pso-protocol` / `pso-zk-circuits` / `pso-vdf`.
