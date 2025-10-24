// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
}

cargo { libname = "wraps" }

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("com.hedera.cryptography.hints")
}

tasks.test {
    environment(
        mapOf(
            // For the TSS lib:
            "TSS_LIB_NUM_OF_CORES" to "10"

            // Path to nova_pp.bin, decider_pp.bin, nova_vp.bin, and decider_vp.bin :
            // FUTURE WORK: once CI team uploads the artifacts to CDN, download them and set the
            // path here:
            // "TSS_LIB_WRAPS_ARTIFACTS_PATH" to "<some-path>",
        )
    )
}
