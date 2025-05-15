// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.report.code-coverage")
    id("org.hiero.gradle.check.spotless")
    id("org.hiero.gradle.check.spotless-kotlin")
}

dependencies {
    implementation(project(":hedera-cryptography-hinTS"))
    implementation(project(":hedera-cryptography-rpm"))
}