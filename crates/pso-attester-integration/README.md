# pso-attester-integration

UniFFI bindings for the PSO **attester** (SRA): consent-box NFT issuance and
SpendingUnit hashing. Built on the generic [`pso-protocol`](https://github.com/psonet/pso-protocol)
consent box + [`pso-chain-abi`](https://github.com/psonet/pso-chain-next) entity
types. **Pure Rust** — no native proving deps — so the compiled library is small
and self-contained, packaged as a Kotlin/JVM JAR and Python wheels.

## API

A single `Attester` object, constructed from the attester's 20-byte on-chain
address. Issuance is **two steps** so a reverted publish can re-issue with
adjusted records without re-deriving the identity:

- `Attester(address)` — bind to the on-chain address.
- `generate_nft_header(seed, consent_pk) -> NftHeader` — run the consent box once
  for the wallet's `consent_pk` (32-byte compressed Grumpkin point): derive the
  owner + the wallet's reconstruction material, draw a fresh NFT id. `seed` is
  ≥ 32 bytes of caller entropy (hashed); vary it per issuance.
- `issue_with_header(header, worldwide_day, currency, base, atto, referrer_addr, spending_records, amendment_records) -> IssuedSpendingUnit`
  — assemble the on-chain `SpendingUnit` + the wallet's `IssuanceReport` and hash
  it. Re-callable with the **same** header but adjusted `sr`/`ar` (record
  fingerprints, each a canonical 32-byte field element): same `su_id` /
  `derivedOwner`, fresh `nft_hash`.

Field elements / compressed points cross the boundary as 32-byte big-endian
`bytes`; addresses as 20 bytes. Non-canonical field inputs (`>=` the BN254 scalar
modulus) are rejected.

## Use

**Kotlin / JVM** — the `pso-attester-integration-kotlin-<tag>.jar` (or GitHub
Packages Maven). Call `NativeLoader.ensureLoaded()` once before any binding:

```kotlin
dependencies { implementation("net.pso:integration.attester:<version>") }

import net.pso.integration.attester.*

NativeLoader.ensureLoaded()
val attester = Attester(addressBytes)               // 20 bytes
val header   = attester.generateNftHeader(seed, consentPk)
val issued   = attester.issueWithHeader(
    header, 20250101u, 978.toUShort(), 100uL, 0uL, ByteArray(20), listOf(srFp), listOf(arFp),
)
```

**Python** — platform wheels (`manylinux_2_34` x86_64/aarch64, macOS arm64):

```python
from pso_attester_integration import Attester

attester = Attester(bytes.fromhex("ab" * 20))
header   = attester.generate_nft_header(seed, consent_pk)
issued   = attester.issue_with_header(header, 20250101, 978, 100, 0,
                                      bytes(20), [sr_fp], [ar_fp])
```

## Build

```bash
cargo build -p pso-attester-integration            # the cdylib + the bindgen bin
cargo test  -p pso-attester-integration            # Rust FFI tests
```

Bindings + packages are produced at release time (CI), never committed:

- **Kotlin JAR:** `kotlin/` (Gradle). Generates the Kotlin bindings via
  `uniffi-bindgen-attester`, bundles the native libs for darwin-arm64 /
  linux-x86_64 / linux-aarch64 under `META-INF/native/<os>-<arch>/`, publishes to
  GitHub Packages Maven. `kotlin/` carries a `mise.toml` for the JDK/Gradle.
- **Python wheels:** `python/` (setuptools). Bundles the generated module + one
  native lib per platform wheel. aarch64 Linux is cross-built via `cargo-zigbuild`.

See the workspace [README](../../README.md) and `ci.yml`'s `build-attester-*`
jobs for the full multi-arch matrix.

## License

[MIT](../../LICENSE)
