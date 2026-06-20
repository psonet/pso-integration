# pso-attester-integration (Python)

Python bindings (via [UniFFI](https://mozilla.github.io/uniffi-rs/)) for the
**PSO attester** — consent-box NFT issuance and SpendingUnit hashing. The same
surface the Kotlin/JVM bindings expose.

The attester core is **pure Rust** (no native proving / barretenberg deps), so
each platform wheel bundles one small, self-contained shared library.

## Install

Platform wheels are published per release (Linux x86_64 / aarch64, macOS arm64):

```bash
pip install pso-attester-integration
```

## Usage

```python
from pso_attester_integration import Attester

# 20-byte on-chain attester (SRA) address.
attester = Attester(bytes.fromhex("ab" * 20))

# Two-step issuance. `seed` is >= 32 bytes of caller entropy (vary per issue);
# `consent_pk` is the wallet's 32-byte compressed consent public key.
header = attester.generate_nft_header(seed, consent_pk)

issued = attester.issue_with_header(
    header,
    worldwide_day=20250101,
    currency=978,            # ISO 4217
    base=100,
    atto=0,
    referrer_addr=bytes(20),
    spending_records=[sr_fp_1, sr_fp_2],   # 32-byte canonical field elements
    amendment_records=[ar_fp_1],
)

su = issued.spending_unit   # the on-chain SpendingUnit struct
report = issued.report      # the wallet's issuance report (nft_hash, nonce, ...)
```

Re-calling `issue_with_header` with the **same** `header` but adjusted
`spending_records` / `amendment_records` (e.g. after a reverted publish) reuses
the SU identity (`su_id` / `derived_owner`) and only recomputes `nft_hash`.

## Build (maintainers)

The generated bindings module + the native lib are produced at build time
(not committed). CI (`build-attester-python` in `.github/workflows/ci.yml`):

1. `cargo build --release` the cdylib for the target.
2. `uniffi-bindgen-attester generate --language python` →
   `pso_attester_integration/pso_attester_integration.py`.
3. stage the lib next to it and `python -m build --wheel` with the target
   `--plat-name`.
