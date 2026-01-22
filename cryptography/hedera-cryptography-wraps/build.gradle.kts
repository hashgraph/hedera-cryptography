// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
    id("DownloadWrapsArtifactTask")
}

cargo { libname = "wraps" }

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
