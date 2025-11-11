// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
    id("DownloadWrapsArtifactTask")
}

cargo { libname = "wraps" }

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("com.hedera.cryptography.hints")
}

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
                    .dir("v0.1.0")
                    .asFile
                    .absolutePath,

            // Commented-out just to provide an example of how to enable swap for WRAPS 2.0.
            // When not set, the proof construction may require up to ~20GB of RAM.
            // "TSS_LIB_WRAPS_SWAP_FILE" to "/tmp/MemoryMapFile",
        )
    )
}
