# pso-integration

[![CI](https://github.com/psonet/pso-integration/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/psonet/pso-integration/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/psonet/pso-integration?display_name=tag&sort=semver)](https://github.com/psonet/pso-integration/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The PSO **client-side integration layer**: the UniFFI bindings, CLIs, and
end-to-end test suite a wallet, an attester (SRA), or CI needs to participate in
the PSO L2. Built on the generic [`pso-protocol`](https://github.com/psonet/pso-protocol)
core, the [`pso-zk-circuits`](https://github.com/psonet/pso-zk-circuits) proving
backend, and the typed entities/ABI from
[`pso-chain-next`](https://github.com/psonet/pso-chain-next) — it owns no
protocol logic of its own; it packages those for non-Rust clients and exercises
them against a live chain.

A Cargo workspace built on the **pso-protocol 0.8 / pso-zk-canonical 0.9** stack:

- **[`crates/pso-mobile-integration`](crates/pso-mobile-integration)** — wallet
  UniFFI surface (`Wallet` / `Consent` objects): derive a consent keypair, build
  per-NFT ownership witnesses, aggregate them into a tribute-draft proof
  (real UltraHonkKeccak via barretenberg, on-device), and the MinRoot VDF for
  Users-pool gating. Ships as an **iOS staticlib + Android cdylib** (the Android
  barretenberg is built from source against the NDK so it links the NDK libc++,
  `std::__ndk1::`).
- **[`crates/pso-attester-integration`](crates/pso-attester-integration)** —
  attester UniFFI surface (`Attester`): consent-box NFT issuance + SpendingUnit
  hashing. **Pure Rust** (no native proving deps) → a self-contained lib per
  platform, packaged as a **Kotlin/JVM JAR** and **Python wheels**.
- **[`cli/pso-zk-cli`](cli/pso-zk-cli)** — offline ZK operations (NFT/key
  generation, single-proof prove/verify).
- **[`cli/pso-attester-cli`](cli/pso-attester-cli)** — attester L2 ops: register
  SpendingRecord / AmendmentRecord, mint SpendingUnit.
- **[`cli/pso-wallet-cli`](cli/pso-wallet-cli)** — wallet L2 ops: prepare SU
  ownership material, aggregate, submit TributeDraft.
- **[`testsuite`](testsuite)** — the `pso-e2e` harness: 38 scenarios driving the
  full SR/AR → SU → wallet-TD lifecycle (plus negative-path / envelope / VDF /
  registry guards) against a running devnet. Owns its own thin eth-clients
  (alloy RPC handle + a `contract_errors` decoder that reuses `pso-chain-abi`'s
  generated error types). The binary is the artifact pso-chain CI runs.

## Layout

```
pso-integration/
├── Cargo.toml                       # virtual workspace + [workspace.dependencies] (0.8/0.9 stack)
├── crates/
│   ├── pso-mobile-integration/      # wallet UniFFI (Wallet/Consent) + barretenberg + MinRoot VDF
│   │                                # → iOS staticlib + Android cdylib
│   └── pso-attester-integration/    # attester UniFFI (Attester); pure Rust
│       ├── kotlin/                  # Gradle subproject → JVM JAR (GitHub Packages Maven)
│       └── python/                  # setuptools → platform wheels (pip)
├── cli/
│   ├── pso-zk-cli/                  # offline ZK ops
│   ├── pso-attester-cli/            # attester L2 ops (register SR/AR, mint SU)
│   └── pso-wallet-cli/              # wallet L2 ops (prepare-su, aggregate, submit-td)
└── testsuite/                       # `pso-e2e` harness + its own eth-client layer
```

## Build

```bash
cargo build --workspace
cargo test  --workspace        # node-free unit + framework tests
```

`pso-mobile-integration` links C++ barretenberg (via `pso-zk-backend`), so it
needs a C++ toolchain (cmake/clang) and network access (noir git deps + first-run
SRS). `pso-attester-integration` and the CLIs are pure Rust.

## Client packages

Non-Rust clients consume the UniFFI bindings, published per release (and to the
relevant registry). Generated bindings are build-time artifacts — never committed.

- **Attester — Kotlin/JVM:** the `pso-attester-integration-kotlin-<tag>.jar`
  (UniFFI Kotlin bindings + bundled native libs for `darwin-arm64` /
  `linux-x86_64` / `linux-aarch64`), also on GitHub Packages Maven. Call
  `NativeLoader.ensureLoaded()` before any binding.
  ```kotlin
  dependencies { implementation("net.pso:integration.attester:<version>") }
  ```
- **Attester — Python:** platform wheels (`manylinux_2_34` x86_64/aarch64,
  macOS arm64).
  ```bash
  pip install pso_attester_integration-<version>-py3-none-manylinux_2_34_x86_64.whl
  ```
- **Mobile (wallet) — iOS / Android:** the `libpso_mobile_integration.{a,so}`
  slices attached to the release, plus `uniffi-bindgen-mobile` to emit the
  Kotlin / Swift bindings.

## Running `pso-e2e`

The suite is client-only — point it at a running `pso-chain --dev` devnet (it
self-registers its attester via the admin key):

```bash
pso-e2e \
  --rpc-url       http://127.0.0.1:8546 \   # attesters pool
  --actor-rpc-url http://127.0.0.1:8545 \   # users pool
  --chain-id      9900501 \
  --admin-key     0xac09…  --attester-key 0x59c6… \
  --only S001                               # optional scenario filter
```

`pso-e2e --list` prints every scenario without touching the chain. See
[`testsuite/README.md`](testsuite/README.md) for the scenario surface.

## Verifying releases

Releases ship sigstore cosign signatures + SLSA build-provenance attestations for
every attached artifact — the `pso-e2e` binaries, the mobile slices (best-effort
matrix), `uniffi-bindgen-mobile`, the Attester Kotlin JAR, the Attester Python
wheels, and `SHA256SUMS`. The JAR/wheels are signed as units; their bundled
native libs are verified transitively via the artifact's SHA-256. See
[SECURITY.md](SECURITY.md) for the threat model and the full recipe.

Quick check (JAR):

```sh
TAG=v0.9.0
ARTIFACT="pso-attester-integration-kotlin-$TAG.jar"
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

[MIT](LICENSE) — same as `pso-protocol` / `pso-zk-circuits` / `pso-vdf` / `pso-poseidon`.
