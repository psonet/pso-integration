// Gradle subproject that bundles the UniFFI Kotlin bindings for
// pso-sra-integration into a JAR alongside dynamic native libs
// (libpso_sra_integration.dylib on darwin, .so on linux) so a
// vanilla Kotlin/JVM consumer can `System.load(...)` them via JNI.
//
// SRA is server-side, JVM-only — no iOS / Android / Windows slices.
//
// Inputs (staged by the CI job `build-sra-kotlin-jar` before `gradle build`):
//   - $rootDir/uniffi-bindgen-sra                                  — host-arch bindgen binary
//   - $rootDir/native/darwin-arm64/libpso_sra_integration.dylib
//   - $rootDir/native/linux-x86_64/libpso_sra_integration.so
//   - $rootDir/native/linux-aarch64/libpso_sra_integration.so
//
// The build performs three steps:
//   1. `generateKotlinBindings` runs `uniffi-bindgen-sra generate
//      --language kotlin --library <host slice>` and lays the
//      output under build/generated/kotlin/. (UniFFI's bindgen only
//      needs *one* of the dynamic libs to extract the component
//      metadata — all slices expose the same UniFFI scaffolding
//      symbols.)
//   2. `stageNativeLibraries` copies the three dynamic libs into
//      build/staged-resources/META-INF/native/<os>-<arch>/ so they
//      end up inside the JAR at well-known paths NativeLoader can
//      extract + System.load at runtime.
//   3. The standard `jar` task picks both the compiled Kotlin
//      classes and the staged resources up automatically.
//
// `gradle build` from the CI job will run all three.

plugins {
    kotlin("jvm") version "2.1.10"
    `java-library`
}

group = "net.pso.zk"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.18.1")
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
}

// Path layout staged by CI. Override via `-PnativeStageDir=...`
// when iterating locally.
val nativeStageDir = (findProperty("nativeStageDir") as String?)
    ?: "${rootDir}/native"
val bindgenBinary = (findProperty("bindgenBinary") as String?)
    ?: "${rootDir}/uniffi-bindgen-sra"

// Pick any one of the three dynamic libs for `--library`. The
// linux-x86_64 .so is the natural default because the CI host
// running gradle is ubuntu-latest; local dev on macOS overrides
// via `-PbindgenLibraryArchive=.../libpso_sra_integration.dylib`.
val bindgenLibraryArchive = (findProperty("bindgenLibraryArchive") as String?)
    ?: "${nativeStageDir}/linux-x86_64/libpso_sra_integration.so"

val kotlinBindingsDir = layout.buildDirectory.dir("generated/kotlin")

val generateKotlinBindings = tasks.register<Exec>("generateKotlinBindings") {
    description = "Run uniffi-bindgen-sra to emit Kotlin bindings"
    group = "build"

    val outDir = kotlinBindingsDir.get().asFile
    outputs.dir(outDir)
    inputs.file(bindgenBinary)
    inputs.file(bindgenLibraryArchive)
    inputs.file("uniffi.toml")

    doFirst {
        outDir.mkdirs()
    }

    commandLine(
        bindgenBinary,
        "generate",
        "--library",
        bindgenLibraryArchive,
        "--language",
        "kotlin",
        "--out-dir",
        outDir.absolutePath,
        "--config",
        "${projectDir}/uniffi.toml",
    )
}

sourceSets {
    main {
        kotlin.srcDir(kotlinBindingsDir)
    }
}

tasks.named("compileKotlin") {
    dependsOn(generateKotlinBindings)
}

val stageNativeLibraries = tasks.register<Copy>("stageNativeLibraries") {
    description = "Copy the 3 cross-compiled dynamic libs into the JAR resources"
    group = "build"

    from(nativeStageDir) {
        include("darwin-arm64/libpso_sra_integration.dylib")
        include("linux-x86_64/libpso_sra_integration.so")
        include("linux-aarch64/libpso_sra_integration.so")
    }
    into(layout.buildDirectory.dir("staged-resources/META-INF/native"))
}

sourceSets {
    main {
        resources.srcDir(layout.buildDirectory.dir("staged-resources"))
    }
}

tasks.named("processResources") {
    dependsOn(stageNativeLibraries)
}

tasks.named<Jar>("jar") {
    archiveBaseName.set("pso-sra-integration-kotlin")
    archiveVersion.set("")
}
