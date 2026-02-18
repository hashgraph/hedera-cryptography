// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.application")
    id("org.hiero.gradle.feature.shadow")
    id("org.hiero.gradle.feature.jpackage")
}

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("org.junit.jupiter.params")
    requires("org.mockito")
    requires("org.mockito.junit.jupiter")
}

application.mainClass = "com.hedera.cryptography.ceremony.Orchestrator"

javaModulePackaging {
    // Bouncy Castle JARs fail as: jlink failed with: Error: signed modular JAR is currently not
    // supported:
    jlinkOptions.addAll("--ignore-signing-information")
}
