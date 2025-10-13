// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
}

cargo { libname = "wraps" }

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("org.junit.jupiter.params")
}

tasks.test {
    environment(
        mapOf(
            // For the TSS lib:
            "TSS_LIB_NUM_OF_CORES" to "10"
        )
    )
}
