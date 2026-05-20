package net.pso.zk.integration.mobile

import kotlin.test.Test

class SmokeTest {

    @Test
    fun `NativeLoader loads the bundled host slice and UniFFI can call into it`() {
        NativeLoader.ensureLoaded()
        // `uniffiEnsureInitialized()` calls
        // `ffi_pso_mobile_integration_uniffi_contract_version()` via JNA
        // and asserts the version matches what the Kotlin bindings were
        // generated against. If the native lib is not visible to JNA the
        // call throws UnsatisfiedLinkError; if the ABI is mismatched it
        // throws RuntimeException("UniFFI contract version mismatch").
        // That is the only signal the smoke test needs — any class-init
        // failure would surface here before any subsequent assertion
        // could run.
        uniffiEnsureInitialized()
    }
}
