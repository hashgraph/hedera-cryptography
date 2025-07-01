// SPDX-License-Identifier: Apache-2.0
plugins { id("org.hiero.gradle.build") version "0.4.5" }

rootProject.name = "hedera-cryptography"

javaModules {
    directory("common") { group = "com.hedera.common" }
    directory("cryptography") { group = "com.hedera.cryptography" }
}
