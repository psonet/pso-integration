package net.pso.integration.agent

import kotlin.test.Test

class AttesterIntegrationTest {

    @Test
    fun `NativeLoader loads the bundled host slice`() {
        // `NativeLoader.ensureLoaded()` extracts the appropriate native
        // lib from `META-INF/native/<os-arch>/` and calls
        // `System.load(extractedPath)` plus
        // `System.setProperty("uniffi.component.<...>.libraryOverride", path)`
        // so JNA's subsequent dlopen can find it. If the JAR's native
        // payload is missing for this host, or the lib fails to load
        // for any reason (ABI mismatch, missing transitive deps), this
        // throws — which is the signal the smoke test needs.
        //
        // We do not additionally call into the UniFFI bindings here
        // because `uniffiEnsureInitialized` is generated as `internal`
        // and isn't visible from the test source set.
        NativeLoader.ensureLoaded()
    }
}
