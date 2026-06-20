// Gradle subproject that bundles the UniFFI Kotlin bindings for
// pso-attester-integration into a JAR alongside dynamic native libs
// (libpso_attester_integration.dylib on darwin, .so on linux) so a
// vanilla Kotlin/JVM consumer can `System.load(...)` them via JNI.
//
// Attester is server-side, JVM-only — no iOS / Android / Windows slices.
//
// Inputs (staged by the CI job `build-attester-kotlin-jar` before `gradle build`):
//   - $rootDir/uniffi-bindgen-attester                                  — host-arch bindgen binary
//   - $rootDir/native/darwin-arm64/libpso_attester_integration.dylib
//   - $rootDir/native/linux-x86_64/libpso_attester_integration.so
//   - $rootDir/native/linux-aarch64/libpso_attester_integration.so
//
// The build performs three steps:
//   1. `generateKotlinBindings` runs `uniffi-bindgen-attester generate
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
    `maven-publish`
}

group = "net.pso"
// CI passes the release version via `-PreleaseVersion=<x.y.z>` (the
// Rust workspace / git-tag version, sans the `v` prefix) so the
// published Maven coordinate tracks the rest of the release. Local
// builds with no property fall back to a dev placeholder.
version = (findProperty("releaseVersion") as String?) ?: "0.1.0-LOCAL"

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
    ?: "${rootDir}/uniffi-bindgen-attester"

// Pick any one of the three dynamic libs for `--library`. The
// linux-x86_64 .so is the natural default because the CI host
// running gradle is ubuntu-latest; local dev on macOS overrides
// via `-PbindgenLibraryArchive=.../libpso_attester_integration.dylib`.
val bindgenLibraryArchive = (findProperty("bindgenLibraryArchive") as String?)
    ?: "${nativeStageDir}/linux-x86_64/libpso_attester_integration.so"

val kotlinBindingsDir = layout.buildDirectory.dir("generated/kotlin")

val generateKotlinBindings = tasks.register<Exec>("generateKotlinBindings") {
    description = "Run uniffi-bindgen-attester to emit Kotlin bindings"
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
        include("darwin-arm64/libpso_attester_integration.dylib")
        include("linux-x86_64/libpso_attester_integration.so")
        include("linux-aarch64/libpso_attester_integration.so")
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
    archiveBaseName.set("pso-attester-integration-kotlin")
    // Empty so the local archive path stays stable
    // (build/libs/pso-attester-integration-kotlin.jar) regardless of
    // version — the CI staging step renames it with the `-v<x.y.z>`
    // release suffix. maven-publish derives the *published* filename
    // from the coordinate (artifactId + version), not this archive
    // name, so an empty archiveVersion does not affect the Maven push.
    archiveVersion.set("")
}

// Publish the bindings JAR (Kotlin classes + bundled native libs) to
// the repo's GitHub Packages Maven registry as
// net.pso:integration.attester:<version>. CI provides the
// GITHUB_* env vars; the workflow-level `packages: write` permission
// authorises the push.
publishing {
    publications {
        create<MavenPublication>("gpr") {
            // Maven coordinate: net.pso:integration.attester:<version>.
            // Independent of the local JAR archive name
            // (pso-attester-integration-kotlin.jar) and the Rust crate name
            // (pso_attester_integration) — maven-publish names the published
            // file from the coordinate.
            artifactId = "integration.attester"
            from(components["java"])

            // POM metadata — required for a well-formed published artifact
            // (Maven Central / consumers surface these).
            pom {
                name.set("PSO Attester Integration (Kotlin)")
                description.set(
                    "UniFFI Kotlin/JVM bindings for the PSO attester: consent-box " +
                        "NFT issuance + SpendingUnit hashing, with bundled native libs.",
                )
                url.set("https://github.com/psonet/pso-integration")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        id.set("psonet")
                        name.set("PSO")
                        email.set("dev@pso.network")
                        organization.set("PSO")
                        organizationUrl.set("https://github.com/psonet")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/psonet/pso-integration.git")
                    developerConnection.set("scm:git:ssh://git@github.com/psonet/pso-integration.git")
                    url.set("https://github.com/psonet/pso-integration")
                }
            }
        }
    }
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri(
                "https://maven.pkg.github.com/" +
                    (System.getenv("GITHUB_REPOSITORY") ?: "psonet/pso-integration"),
            )
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }
        }
    }
}
