// SPDX-License-Identifier: Apache-2.0
plugins {
    id("application")
    id("org.hiero.gradle.module.library")
}

testModuleInfo { requires("org.junit.jupiter.api") }

application.mainClass = "com.hedera.cryptography.eckeygen.KeyGen"
