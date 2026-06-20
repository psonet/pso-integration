"""PSO attester integration — Python bindings (UniFFI).

Consent-box NFT issuance + SpendingUnit hashing for the PSO attester (SRA),
the same surface the Kotlin/JVM bindings expose. Pure-Rust core (no native
proving deps), so the wheel bundles one self-contained shared library per
platform alongside the generated module.

The generated `pso_attester_integration` submodule loads
`libpso_attester_integration.{so,dylib}` from this package directory at import
time (see UniFFI's `_uniffi_load_indirect`), so the native lib MUST sit next to
the generated `.py` inside this package — which the wheel build guarantees.
"""

from .pso_attester_integration import *  # noqa: F401,F403
