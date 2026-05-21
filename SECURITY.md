# Security policy

## Release signing

Starting with the first release tagged after this file lands (expected: **v0.3.7**, the cog-bumped patch following PR `release/sigstore-signing`), every artifact attached to a `pso-integration` GitHub Release is signed with [sigstore cosign](https://docs.sigstore.dev/cosign/overview/) keyless OIDC and carries an [SLSA v1.0](https://slsa.dev/spec/v1.0/) build-provenance attestation minted by `actions/attest-build-provenance`.

### Signed artifacts

For each release ≥ the cutoff, the following files ship alongside the regular release assets:

**End-to-end binaries:**

| File | What it is |
|---|---|
| `pso-e2e-linux-aarch64` | E2E test runner, Linux arm64. |
| `pso-e2e-linux-x86_64` | E2E test runner, Linux amd64. |

**Mobile slices (best-effort matrix; whichever produced):**

| File | What it is |
|---|---|
| `pso-mobile-integration-ios-arm64-libpso_mobile_integration.a` | iOS device static lib. |
| `pso-mobile-integration-ios-sim-arm64-libpso_mobile_integration.a` | iOS Apple-Silicon simulator static lib. |
| `pso-mobile-integration-android-arm64-v8a-libpso_mobile_integration.so` | Android arm64 shared lib. |
| `pso-mobile-integration-android-x86_64-libpso_mobile_integration.so` | Android x86_64 shared lib. |

**Bindgen binaries:**

| File | What it is |
|---|---|
| `uniffi-bindgen-mobile-linux-x86_64` | UniFFI bindgen, Linux x86_64. |
| `uniffi-bindgen-mobile-darwin-arm64` | UniFFI bindgen, Apple Silicon. |

**SRA Kotlin bindings:**

| File | What it is |
|---|---|
| `pso-sra-integration-kotlin.jar` | UniFFI-generated Kotlin bindings + 3 bundled native libs (`META-INF/native/<os>-<arch>/`). |

**Common:**

| File | What it is |
|---|---|
| `SHA256SUMS` | SHA-256 of every other file attached to the release. |
| `<artifact>.sig` / `<artifact>.pem` | cosign blob signature + Fulcio cert per artifact (one pair per file above). |

Build-provenance attestations are not attached to the Release — they live in GitHub's attestation store and are queried via `gh attestation verify`.

### What "signing the JAR" means

The Kotlin JAR ships three native dynamic libraries inside it under `META-INF/native/<os>-<arch>/`. The signature attaches to **the JAR file as a whole**, not to each bundled native lib individually. This is intentional — per the T-0020 spec (2026-05-20 implementation finding):

- The JAR is the unit consumers download, extract, and load. Per-native-lib signatures inside the JAR would not be reachable in any practical verification flow (the JVM loader extracts them at runtime; nothing checks signatures at that step).
- The JAR's signature pins the entire bundle including the native libs. Tampering with any byte inside the JAR — including swapping one of the bundled `.so`/`.dylib` files — invalidates the signature.
- The bundled native libs are verified **transitively** via the JAR's SHA-256: a verified JAR implies untampered native libs by construction.

### Matrix-aware signing

The mobile build matrix (`build-mobile-ios`, `build-mobile-android`) runs with `continue-on-error: true` because the upstream `barretenberg-rs` cross-toolchain has occasional regressions on individual targets. The signing pipeline tolerates this: **whichever subset of mobile slices made it through the matrix gets signed**; missing slices contribute zero signatures. The post-publish `verify-release` job then verifies every signed pair on the release; it fails if any signature is invalid OR if zero artifacts were signed.

### Threat model

The signing pipeline protects against:

- **Tampered binaries on the Release page.** A re-uploaded JAR, e2e binary, mobile slice, or `SHA256SUMS` won't verify against the original cert + sig.
- **A compromised release token.** A maintainer who can push tags cannot mint a sigstore signature whose Fulcio cert identity matches `https://github.com/psonet/pso-integration/.github/workflows/ci.yml@refs/heads/main` (the cog flow) or `@refs/tags/vX.Y.Z` (a manual tag-push re-release). Those identities are only obtainable from inside a GitHub Actions run of this repo's `ci.yml` workflow.
- **A tampered native lib inside the JAR.** Modifying any byte of the JAR — including the bundled `.so`/`.dylib` files under `META-INF/native/` — invalidates the JAR's cosign signature.
- **A typo or mis-targeted action update** silently weakening verification. The post-publish `verify-release` job hard-fails the workflow on any bad signature.

It does **not** protect against:

- A compromise of `github.com/psonet/pso-integration` itself (an attacker with push access to `main` can edit the workflow to remove or weaken signing).
- A compromise of the sigstore public-good trust root (Fulcio CA, Rekor transparency log).
- A `barretenberg-rs` / `noir_rs` upstream supply-chain compromise. The mobile slices and JAR-bundled native libs are built against whichever prebuilt FFI binaries `barretenberg-rs`'s `build.rs` fetches at CI time. The signature attests "this is the binary CI produced on this tagged run," not "this binary contains untampered upstream code."
- The container image pushed to GHCR by `release-image`. That image has its own GHCR provenance (separate flow); cosign signing of GHCR images is out of scope for this PR.
- Existing (pre-cutoff) releases. Those are **not** retroactively signed.

### Verification recipe

You need [cosign](https://docs.sigstore.dev/cosign/installation/) and [`gh`](https://cli.github.com/) on `$PATH`.

```sh
REPO=psonet/pso-integration
TAG=v0.3.7  # or any release ≥ the cutoff

# JAR verification (most common consumer path).
ARTIFACT=pso-sra-integration-kotlin.jar
gh release download "$TAG" --repo "$REPO" \
  --pattern "$ARTIFACT" \
  --pattern "$ARTIFACT.sig" \
  --pattern "$ARTIFACT.pem"

cosign verify-blob \
  --certificate "$ARTIFACT.pem" \
  --signature   "$ARTIFACT.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/psonet/pso-integration/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARTIFACT"

# Bulk-verify everything via SHA256SUMS:
gh release download "$TAG" --repo "$REPO" --pattern 'SHA256SUMS*'
cosign verify-blob \
  --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp \
    '^https://github\.com/psonet/pso-integration/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
gh release download "$TAG" --repo "$REPO"  # download everything else
shasum -a 256 -c SHA256SUMS

# Optional: SLSA build-provenance attestation.
gh attestation verify "$ARTIFACT" --repo "$REPO"
```

CI's own `verify-release` job runs the same loop on every published release; a green `verify-release` is your signal that the regex above is the correct one.

### Retroactive signing

Releases tagged **before** the cutoff are not signed. Backfilling would mint signatures whose Fulcio identity reads "a manual workflow_dispatch on YYYY-MM-DD by a maintainer," not "a tag-triggered run of the original release," which is weaker provenance than the absence of a signature.

## Reporting vulnerabilities

For security issues in `pso-integration` itself (not the signing pipeline), open a [private security advisory](https://github.com/psonet/pso-integration/security/advisories/new) on GitHub. Do not file a public issue.

## References

- [sigstore docs](https://docs.sigstore.dev/)
- [SLSA v1.0 specification](https://slsa.dev/spec/v1.0/)
- [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
- [`sigstore/cosign-installer`](https://github.com/sigstore/cosign-installer)
