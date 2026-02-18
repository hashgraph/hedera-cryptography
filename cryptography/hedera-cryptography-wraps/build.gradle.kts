// SPDX-License-Identifier: Apache-2.0
import org.hiero.gradle.extensions.CargoExtension.Companion.hostArch
import org.hiero.gradle.extensions.CargoExtension.Companion.hostOs
import org.hiero.gradle.extensions.CargoToolchain
import org.hiero.gradle.tasks.CargoBuildTask

// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
    id("DownloadWrapsArtifactTask")
}

cargo {
    libname = "wraps"
    appname = "ceremony"
}

testModuleInfo { requires("org.junit.jupiter.api") }

// remove license header check for rust files
spotless { format("rust") { clearSteps() } }

tasks.test {
    dependsOn("downloadWrapsArtifactTask")
    environment(
        mapOf(
            // For the TSS lib:
            "TSS_LIB_NUM_OF_CORES" to "10",

            // Path to nova_pp.bin, decider_pp.bin, nova_vp.bin, and decider_vp.bin :
            "TSS_LIB_WRAPS_ARTIFACTS_PATH" to
                (tasks.named("downloadWrapsArtifactTask").get().property("wrapsDir")
                        as DirectoryProperty)
                    .get()
                    .dir("v0.2.0")
                    .asFile
                    .absolutePath,

            // Cache the proving key so we can construct proof multiple times in the same JVM
            // w/o having to reload the proving key, which takes up to 27 minutes.
            "TSS_LIB_WRAPS_ARTIFACTS_CACHE_ENABLED" to "true",

            // Commented-out just to provide an example of how to enable swap for WRAPS 2.0.
            // When not set, the proof construction may require up to ~16GB of RAM.
            // "TSS_LIB_WRAPS_SWAP_FILE" to "/tmp/MemoryMapFile",
        )
    )
}

tasks.processResources { exclude("com/hedera/nativelib/ceremony/**") }

// export native binaries built with rust as separate artifacts
configurations.consumable("nativeBinElements") {
    attributes.attribute(Usage.USAGE_ATTRIBUTE, objects.named("native-bin"))
    val packageAllTargets =
        providers.gradleProperty("packageAllTargets").getOrElse("false").toBoolean()
    CargoToolchain.entries.forEach { target ->
        // conditions are the same as here:
        // https://github.com/hiero-ledger/hiero-gradle-conventions/blob/41c0ec4b47970d5b7e7218ae3b69760e9f5dd633/src/main/kotlin/org/hiero/gradle/extensions/CargoExtension.kt#L95-L97
        if (packageAllTargets || (target.os == hostOs() && target.arch == hostArch())) {
            outgoing.artifact(
                tasks
                    .named<CargoBuildTask>(
                        "cargoBuild${target.name.replaceFirstChar(Char::titlecase)}"
                    )
                    .flatMap { it.destinationDirectory }
            )
        }
    }
}
