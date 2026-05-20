// Gradle subproject that bundles the UniFFI Kotlin bindings for
// pso-mobile-integration into a JAR alongside the native static
// archives consumed by JNI/JNA on the host.
//
// Inputs (staged by the CI job `build-kotlin-jar` before `gradle build`):
//   - $rootDir/uniffi-bindgen-mobile        — host-arch bindgen binary
//   - $rootDir/native/<os>-<arch>/libpso_mobile_integration.a  (×3)
//
// The build performs three steps:
//   1. `generateKotlinBindings` runs `uniffi-bindgen-mobile generate
//      --language kotlin --library <one of the .a files>` and lays
//      the output under src/main/kotlin/. (UniFFI's bindgen only
//      needs *one* of the native archives to extract the component
//      metadata — they all expose the same UniFFI scaffolding
//      symbols.)
//   2. `stageNativeArchives` copies the three .a files into
//      src/main/resources/META-INF/native/<os>-<arch>/ so they end
//      up inside the JAR at well-known paths a downstream loader
//      can extract at runtime.
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
    ?: "${rootDir}/uniffi-bindgen-mobile"

// Pick any one of the three .a files for `--library` — UniFFI only
// reads component metadata, so the host-arch slice is the natural
// choice (no cross-arch loader gymnastics at build time).
val bindgenLibraryArchive = (findProperty("bindgenLibraryArchive") as String?)
    ?: "${nativeStageDir}/linux-x86_64/libpso_mobile_integration.a"

val kotlinBindingsDir = layout.buildDirectory.dir("generated/kotlin")

val generateKotlinBindings = tasks.register<Exec>("generateKotlinBindings") {
    description = "Run uniffi-bindgen-mobile to emit Kotlin bindings"
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

val stageNativeArchives = tasks.register<Copy>("stageNativeArchives") {
    description = "Copy the 3 cross-compiled static archives into the JAR resources"
    group = "build"

    from(nativeStageDir) {
        include("darwin-arm64/libpso_mobile_integration.a")
        include("linux-x86_64/libpso_mobile_integration.a")
        include("linux-aarch64/libpso_mobile_integration.a")
    }
    into(layout.buildDirectory.dir("staged-resources/META-INF/native"))
}

sourceSets {
    main {
        resources.srcDir(layout.buildDirectory.dir("staged-resources"))
    }
}

tasks.named("processResources") {
    dependsOn(stageNativeArchives)
}

tasks.named<Jar>("jar") {
    archiveBaseName.set("pso-mobile-integration-kotlin")
    archiveVersion.set("")
}
