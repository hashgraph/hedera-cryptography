// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
}

cargo { libname = "rpm" }

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("com.hedera.cryptography.hints")
}
