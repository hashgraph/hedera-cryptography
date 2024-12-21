// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.base.lifecycle")
    id("org.hiero.gradle.base.jpms-modules")
    id("org.hiero.gradle.check.spotless")
    id("org.hiero.gradle.check.spotless-kotlin")
}

val junit5 = "5.11.4"
val mockito = "5.14.2"

dependencies.constraints {
    api("com.github.spotbugs:spotbugs-annotations:4.7.3") {
        because("com.github.spotbugs.annotations")
    }
    api("com.google.code.gson:gson:2.11.0") { because("com.google.gson") }
    api("jakarta.inject:jakarta.inject-api:2.0.1") { because("jakarta.inject") }
    api("org.bouncycastle:bcprov-jdk18on:1.79") { because("org.bouncycastle.provider") }
    api("org.junit.jupiter:junit-jupiter-api:$junit5") { because("org.junit.jupiter.api") }
    api("org.junit.jupiter:junit-jupiter-engine:$junit5") { because("org.junit.jupiter.engine") }
    api("org.mockito:mockito-core:$mockito") { because("org.mockito") }
    api("org.mockito:mockito-junit-jupiter:$mockito") { because("org.mockito.junit.jupiter") }
}
