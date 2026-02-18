// SPDX-License-Identifier: Apache-2.0
pluginManagement { includeBuild("gradle/plugins") }

plugins { id("org.hiero.gradle.build") version "0.6.3" }

buildscript { dependencies.constraints { classpath("com.gradleup.nmcp:nmcp:1.2.1!!") } }

rootProject.name = "hedera-cryptography"

javaModules {
    directory("common") { group = "com.hedera.common" }
    directory("cryptography") { group = "com.hedera.cryptography" }
}
