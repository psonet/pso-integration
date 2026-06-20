package net.pso.integration.agent

import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Extracts the host-arch dynamic library bundled inside the JAR at
 * `META-INF/native/<os>-<arch>/libpso_attester_integration.{dylib,so}`,
 * registers it with the JVM via `System.load`, and points UniFFI's
 * generated JNA `Native.register(...)` call at the extracted file
 * via the `uniffi.component.pso_attester_integration.libraryOverride`
 * system property.
 *
 * Both hooks are needed:
 *   - `System.load(...)` — for any direct-JNI consumer that drops down
 *     past the UniFFI surface.
 *   - `libraryOverride` — for UniFFI itself, whose generated
 *     `findLibraryName(...)` reads this property first before falling
 *     back to a bare `dlopen("pso_attester_integration")`, which would
 *     fail in a JAR-distributed setup (the dylib lives in a tempdir,
 *     not on the OS library search path).
 *
 * Call [ensureLoaded] once before invoking any UniFFI-generated
 * function. Idempotent within a JVM lifetime.
 */
object NativeLoader {

    private val loaded = AtomicBoolean(false)

    fun ensureLoaded() {
        if (!loaded.compareAndSet(false, true)) return

        val osArch = detectOsArch()
        val ext = if (osArch.startsWith("darwin")) "dylib" else "so"
        val resource = "/META-INF/native/$osArch/libpso_attester_integration.$ext"

        val stream = NativeLoader::class.java.getResourceAsStream(resource)
            ?: error("Native library not found in JAR: $resource (host=$osArch)")

        val tempFile = Files.createTempFile(
            "libpso_attester_integration",
            ".$ext",
        ).toFile().apply { deleteOnExit() }

        stream.use { input ->
            Files.copy(
                input,
                tempFile.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
            )
        }

        System.load(tempFile.absolutePath)
        System.setProperty(
            "uniffi.component.pso_attester_integration.libraryOverride",
            tempFile.absolutePath,
        )
    }

    private fun detectOsArch(): String {
        val os = System.getProperty("os.name").lowercase()
        val arch = System.getProperty("os.arch").lowercase()
        val osTag = when {
            "mac" in os || "darwin" in os -> "darwin"
            "linux" in os -> "linux"
            else -> error("Unsupported OS: $os")
        }
        val archTag = when (arch) {
            "aarch64", "arm64" -> if (osTag == "darwin") "arm64" else "aarch64"
            "x86_64", "amd64" -> "x86_64"
            else -> error("Unsupported arch: $arch")
        }
        return "$osTag-$archTag"
    }
}
