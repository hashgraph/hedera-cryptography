// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.benchmark")
    id("org.hiero.gradle.feature.test-fixtures")
}

mainModuleInfo { runtimeOnly("com.hedera.cryptography.altbn128") }

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("org.junit.jupiter.params")
    requires("org.mockito")
    requires("com.hedera.cryptography.utils.test.fixtures")
    requires("com.hedera.cryptography.altbn128.test.fixtures")
}

jmhModuleInfo {
    requires("com.hedera.cryptography.bls.test.fixtures")
    requires("com.hedera.cryptography.utils.test.fixtures")
}
