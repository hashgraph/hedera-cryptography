// SPDX-License-Identifier: Apache-2.0
pluginManagement {
    repositories {
        gradlePluginPortal()
        maven("https://central.sonatype.com/repository/maven-snapshots")
    }
    includeBuild("gradle/plugins")
}

buildscript {
    configurations.classpath { resolutionStrategy.cacheChangingModulesFor(0, "seconds") }
}

plugins { id("org.hiero.gradle.build") version "0.7.1-SNAPSHOT" }

rootProject.name = "hedera-cryptography"

javaModules {
    directory("common") { group = "com.hedera.common" }
    directory("cryptography") { group = "com.hedera.cryptography" }
}
