// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.test-fixtures")
    id("org.hiero.gradle.feature.benchmark")
}

mainModuleInfo { runtimeOnly("com.hedera.cryptography.altbn128") }

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("com.hedera.cryptography.utils.test.fixtures")
    requires("org.mockito")
}

jmhModuleInfo { requires("com.hedera.cryptography.tss.test.fixtures") }
