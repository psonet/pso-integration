package net.pso.zk.integration.mobile

/**
 * Locates the platform-specific static archive bundled inside the JAR
 * at META-INF/native/<os>-<arch>/libpso_mobile_integration.a.
 *
 * Unlike pso-sra-integration which ships a dynamic library (.so /
 * .dylib) loadable through JNA's `loadIndirect`, pso-mobile-integration
 * ships *static* archives because the downstream consumers (build
 * tools, repro builds, audit pipelines) link them into their own
 * outputs. This loader therefore exposes the archive path on disk
 * rather than registering it with JNA — extraction-only, no dlopen.
 */
object NativeLoader {

    data class Archive(val osArch: String, val path: java.io.File)

    /**
     * Extracts the host's static archive to a temp file and returns
     * its path. Idempotent within a JVM lifetime.
     */
    @Synchronized
    fun extract(): Archive {
        val os = System.getProperty("os.name").lowercase()
        val arch = System.getProperty("os.arch").lowercase()

        val osArch = when {
            "mac" in os && arch in listOf("aarch64", "arm64") -> "darwin-arm64"
            "linux" in os && arch in listOf("amd64", "x86_64") -> "linux-x86_64"
            "linux" in os && arch == "aarch64" -> "linux-aarch64"
            else -> throw UnsatisfiedLinkError(
                "Unsupported host: os=$os arch=$arch. " +
                "Supported: darwin-arm64, linux-x86_64, linux-aarch64."
            )
        }

        val resourcePath = "/META-INF/native/$osArch/libpso_mobile_integration.a"
        val stream = NativeLoader::class.java.getResourceAsStream(resourcePath)
            ?: throw UnsatisfiedLinkError("Native archive not found in JAR: $resourcePath")

        val tmpDir = java.io.File(
            System.getProperty("java.io.tmpdir"),
            "pso-mobile-integration-native"
        ).apply { mkdirs() }
        val tmpFile = java.io.File(tmpDir, "libpso_mobile_integration.a")
        stream.use { input ->
            java.io.FileOutputStream(tmpFile).use { output ->
                input.copyTo(output)
            }
        }
        tmpFile.deleteOnExit()
        return Archive(osArch, tmpFile)
    }
}
