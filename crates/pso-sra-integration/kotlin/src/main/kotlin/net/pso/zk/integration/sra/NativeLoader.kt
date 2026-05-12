package net.pso.zk.integration.sra

import java.io.File
import java.io.FileOutputStream

/**
 * Extracts the platform-specific native library from JAR resources
 * and registers it for JNA/UniFFI loading.
 *
 * Call [load] once before using any ownership functions.
 */
object NativeLoader {
    private var loaded = false

    @Synchronized
    fun load() {
        if (loaded) return

        val os = System.getProperty("os.name").lowercase()
        val arch = System.getProperty("os.arch").lowercase()

        val (dirName, libName) = when {
            "mac" in os && arch in listOf("aarch64", "arm64") ->
                "darwin-aarch64" to "libpso_sra_integration.dylib"
            "linux" in os && arch in listOf("amd64", "x86_64") ->
                "linux-x86-64" to "libpso_sra_integration.so"
            else -> throw UnsatisfiedLinkError(
                "Unsupported platform: os=$os arch=$arch. " +
                "Supported: macOS ARM64, Linux x86_64."
            )
        }

        val resourcePath = "/native/$dirName/$libName"
        val stream = NativeLoader::class.java.getResourceAsStream(resourcePath)
            ?: throw UnsatisfiedLinkError("Native library not found in JAR: $resourcePath")

        val tmpDir = File(System.getProperty("java.io.tmpdir"), "pso-sra-integration-native")
        tmpDir.mkdirs()
        val tmpFile = File(tmpDir, libName)

        stream.use { input ->
            FileOutputStream(tmpFile).use { output ->
                input.copyTo(output)
            }
        }

        // Point UniFFI's generated loadIndirect() to the extracted file.
        // This uses the built-in override mechanism (findLibraryName checks
        // this property first) and avoids mutating the global jna.library.path.
        System.setProperty(
            "uniffi.component.pso_sra_integration.libraryOverride",
            tmpFile.absolutePath
        )

        tmpFile.deleteOnExit()
        loaded = true
    }
}
