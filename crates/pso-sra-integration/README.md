# SRA Integration

FFI library for computing NFT ownership values using Secp256K1 ECDH
key derivation and Poseidon5 hashing. Produces a Kotlin JVM library
(JAR) with bundled native libraries for macOS ARM64 and Linux x86_64.

## Cryptographic Flow

```
Input:  sra_sk     (Secp256K1 secret key — raw 32 bytes or SEC1 DER encoded)
        consent_pk (Secp256K1 public key — 33-byte compressed or 65-byte uncompressed)

1. Parse and validate inputs
2. ECDH: S = sra_sk * consent_pk  (scalar multiplication on Secp256K1)
3. Generate random nonce          (Fr::random — valid BN256 field element)
4. KDF:  nft_sk = HMAC-SHA256(S, nonce_bytes)
5. Derive nft_pk from nft_sk      (Secp256K1 generator point)
6. Hash: ownership = Poseidon5(pk_x_lo, pk_x_hi, pk_y_lo, pk_y_hi, nonce)
7. Return GeneratedOwnership { nonce: base58, ownership: base58 }
```

## Secret Key Format

The `sra_sk` parameter accepts two formats, auto-detected by length:

- **Raw scalar (32 bytes)** — the private key scalar directly
- **SEC1 DER (>32 bytes)** — RFC 5915 encoded private key

### SEC1 DER Format (39 bytes minimum)

```
30 25           -- SEQUENCE, 37 bytes content
  02 01 01      -- INTEGER version 1
  04 20         -- OCTET STRING, 32 bytes
    [32 bytes of private key scalar]
```

Both formats produce identical results for the same underlying key.

### Prerequisites

### Rust Targets

Install the Rust toolchain and required cross-compilation targets:

```bash
rustup target add aarch64-apple-darwin x86_64-unknown-linux-gnu
```

### Cross-Compilation (zig)

Cross-compiling the Linux native library from macOS requires
[Zig](https://ziglang.org/) and
[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild):

```bash
brew install zig
cargo install cargo-zigbuild
```

The xtask automatically uses `cargo zigbuild` for cross-compilation
targets and `cargo build` for the native host target.

### JDK and Gradle

Building the Kotlin JAR requires:

- **JDK 21+** — `java -version` to verify
- **Gradle 8+** — install via [SDKMAN](https://sdkman.io) or
  [gradle.org](https://gradle.org/install/):

```bash
# SDKMAN (recommended)
sdk install gradle

# Or Homebrew (macOS)
brew install gradle
```

## Building the Kotlin Library

### Using xtask (recommended)

```bash
# Build for the current host platform (default)
cargo xtask build-kotlin

# Build for a specific platform
cargo xtask build-kotlin -t aarch64-apple-darwin
cargo xtask build-kotlin -t x86_64-unknown-linux-gnu

# Build for both platforms (macOS + Linux cross-compilation via zig)
cargo xtask build-kotlin -t aarch64-apple-darwin -t x86_64-unknown-linux-gnu
```

The command performs these steps automatically:

1. Builds the native cdylib (`libpso_sra_integration.dylib` / `.so`)
   for each target via `cargo build` (native) or `cargo zigbuild` (cross)
2. Builds the `uniffi-bindgen-sra` tool
3. Generates Kotlin bindings from the compiled library
4. Copies native libraries into the Gradle project resources
5. Runs `gradle jar` to produce the final JAR

Output JAR: `integrations/pso-sra-integration/kotlin/build/libs/pso-sra-integration-0.1.0.jar`

### Manual Steps

If you prefer to run each step individually:

```bash
# 1. Build native library (use cargo zigbuild for cross-compilation)
cargo build -p pso-sra-integration --release --target aarch64-apple-darwin
cargo zigbuild -p pso-sra-integration --release --target x86_64-unknown-linux-gnu

# 2. Build uniffi-bindgen-sra
cargo build -p pso-sra-integration --bin uniffi-bindgen-sra

# 3. Generate Kotlin bindings
target/debug/uniffi-bindgen-sra generate \
  --library target/aarch64-apple-darwin/release/libpso_sra_integration.dylib \
  --language kotlin \
  --out-dir integrations/pso-sra-integration/kotlin/src/main/kotlin

# 4. Copy native libraries to Gradle resources
mkdir -p integrations/pso-sra-integration/kotlin/src/main/resources/native/darwin-aarch64
cp target/aarch64-apple-darwin/release/libpso_sra_integration.dylib \
   integrations/pso-sra-integration/kotlin/src/main/resources/native/darwin-aarch64/

mkdir -p integrations/pso-sra-integration/kotlin/src/main/resources/native/linux-x86-64
cp target/x86_64-unknown-linux-gnu/release/libpso_sra_integration.so \
   integrations/pso-sra-integration/kotlin/src/main/resources/native/linux-x86-64/

# 5. Build JAR
cd integrations/pso-sra-integration/kotlin && gradle jar
```

## Using the Kotlin Library

Add the JAR to your project's classpath. The library depends on
[JNA](https://github.com/java-native-access/jna) at runtime.

### Gradle dependency

```kotlin
repositories {
    maven { url = uri("https://maven.pkg.github.com/psonet/pso-integration") }
}

dependencies {
    // Published to GitHub Packages by the release pipeline. JNA is a
    // transitive runtime dependency, resolved automatically from the POM.
    implementation("net.pso:integration.agent:0.3.11")
}
```

### Usage

```kotlin
import net.pso.integration.agent.NativeLoader
import net.pso.integration.agent.generateNftOwnership
import net.pso.integration.agent.OwnershipException

// Load native library once at application startup
NativeLoader.load()

// Prepare secret key — either raw 32-byte scalar or SEC1 DER encoded
// Raw 32-byte scalar:
val sraSkBytes = byteArrayOf(/* 32 bytes of private key scalar */)
// Or SEC1 DER encoded (39+ bytes):
// val sraSkBytes = byteArrayOf(0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20, ...)

// Prepare public key (33 bytes compressed or 65 bytes uncompressed)
val consentPkBytes = byteArrayOf(/* Secp256K1 public key bytes */)

try {
    val result = generateNftOwnership(sraSkBytes, consentPkBytes)
    println("Nonce: ${result.nonce}")
    println("Ownership: ${result.ownership}")
} catch (e: OwnershipException) {
    println("Error: ${e.message}")
}
```

## JAR Contents

```
pso-sra-integration-0.1.0.jar
├── net/pso/integration/agent/
│   ├── NativeLoader.class          # Platform-aware library loader
│   └── pso_sra_integration.class   # UniFFI-generated bindings
└── native/
    ├── darwin-aarch64/
    │   └── libpso_sra_integration.dylib
    └── linux-x86-64/
        └── libpso_sra_integration.so
```

## Development

### Running Rust Tests

```bash
cargo test -p pso-sra-integration
```

### Running CI Clippy Checks

```bash
cargo ci-clippy
```

Runs the same clippy lints as CI (`-D warnings`) against the FFI crate.

### Running Kotlin Integration Tests

The Kotlin tests verify that the FFI bindings produce identical outputs
to the Rust implementation using shared test vectors. They require the
JAR to be built first (native library must be present in resources).

```bash
# 1. Build the JAR (at least for the host platform)
cargo xtask build-kotlin

# 2. Run the Kotlin tests
cd integrations/pso-sra-integration/kotlin && gradle test
```

The integration test suite covers:

- **Cross-language determinism** — fixed inputs produce the same
  nonce and ownership hash as the Rust unit test
- **Reproducibility** — repeated calls with the same inputs are consistent
- **Compressed key support** — 33-byte compressed keys produce the
  same result as their 65-byte uncompressed equivalent
- **Random generation** — the non-deterministic path produces valid output
- **Raw key support** — raw 32-byte scalar keys produce the same
  result as their SEC1 DER equivalent
- **Error handling** — invalid inputs throw `OwnershipException`

### Project Structure

```
integrations/pso-sra-integration/
├── src/
│   ├── lib.rs              # FFI entry point + generate_nft_ownership()
│   ├── crypto.rs           # ECDH, KDF, key parsing, nonce generation
│   ├── error.rs            # OwnershipError enum (uniffi::Error)
│   └── bin/
│       └── uniffi-bindgen.rs    # UniFFI binding generator binary
├── kotlin/                 # Gradle project for Kotlin JAR
│   ├── build.gradle.kts
│   ├── settings.gradle.kts
│   ├── uniffi.toml         # UniFFI config (Kotlin package name)
│   └── src/
│       ├── main/kotlin/net/pso/integration/agent/
│       │   └── NativeLoader.kt
│       └── test/kotlin/net/pso/integration/agent/
│           └── SraIntegrationTest.kt
└── Cargo.toml
```

### Supported Platforms

| Platform | Rust Target | Native Library |
|----------|-------------|----------------|
| macOS ARM64 | `aarch64-apple-darwin` | `libpso_sra_integration.dylib` |
| Linux x86_64 | `x86_64-unknown-linux-gnu` | `libpso_sra_integration.so` |

## Security

- Error messages never contain key material or intermediate values
- Input validation: key format auto-detection, DER parsing, and scalar validation handled by k256
- `#![forbid(unsafe_code)]` in Rust source (UniFFI internals excluded)
- Thread-safe: concurrent calls are independent
