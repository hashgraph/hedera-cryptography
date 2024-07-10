/*
 * Copyright (C) 2022-2023 Hedera Hashgraph, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pluginManagement { includeBuild("gradle/plugins") }

plugins { id("com.gradle.enterprise").version("3.10.3") }

rootProject.name = "hedera-bls-cryptography"

/* include(":hedera-bls-api") */

/* include(":hedera-bls-impl") */

/* include(":hedera-bls-rust-jni") */

dependencyResolutionManagement {
  @Suppress("UnstableApiUsage")
  versionCatalogs {
    // The libs of this catalog are the **ONLY** ones that are authorized to be part of the runtime
    // distribution. These libs can be depended on during compilation, or bundled as part of
    // runtime.
    create("libs") {
      // Define the approved version numbers
      // Third-party dependency versions

      // JNI
      version("resource-loader-version", "2.0.2")
      version("jna-version", "5.9.0")

      version("slf4j-version", "2.0.0")
      version("log4j-version", "2.17.2")
      version("commons-lang3-version", "3.12.0")
      version("commons-io-version", "2.11.0")

      // Define the individual libraries
      library("resource-loader", "com.goterl", "resource-loader")
          .versionRef("resource-loader-version")
      library("jna", "net.java.dev.jna", "jna").versionRef("jna-version")
      // Log4j Bundle
      library("log4j-api", "org.apache.logging.log4j", "log4j-api").versionRef("log4j-version")
      library("log4j-core", "org.apache.logging.log4j", "log4j-core").versionRef("log4j-version")
      // Slf4j Bundle
      library("slf4j-api", "org.slf4j", "slf4j-api").versionRef("slf4j-version")
      library("slf4j-nop", "org.slf4j", "slf4j-nop").versionRef("slf4j-version")
      library("commons-lang3", "org.apache.commons", "commons-lang3")
          .versionRef("commons-lang3-version")
      library("commons-io", "commons-io", "commons-io").versionRef("commons-io-version")

      bundle("logging-api", listOf("log4j-api", "slf4j-api"))
      bundle("logging-impl", listOf("log4j-core", "slf4j-nop"))
    }

    create("testLibs") {
      version("junit-jupiter-version", "5.9.2")
      version("mockito-version", "5.1.1")
      version("assertj-version", "3.24.2")

      library("junit-jupiter-api", "org.junit.jupiter", "junit-jupiter-api")
          .versionRef("junit-jupiter-version")
      library("junit-jupiter-params", "org.junit.jupiter", "junit-jupiter-params")
          .versionRef("junit-jupiter-version")
      library("junit-jupiter-engine", "org.junit.jupiter", "junit-jupiter-engine")
          .versionRef("junit-jupiter-version")

      library("mockito-core", "org.mockito", "mockito-core").versionRef("mockito-version")
      library("mockito-junit-jupiter", "org.mockito", "mockito-junit-jupiter")
          .versionRef("mockito-version")

      library("assertj-core", "org.assertj", "assertj-core").versionRef("assertj-version")

      bundle("junit", listOf("junit-jupiter-api", "junit-jupiter-params", "junit-jupiter-engine"))
      bundle("mockito", listOf("mockito-core", "mockito-junit-jupiter"))
      bundle("assertj", listOf("assertj-core"))
    }
  }
}

gradleEnterprise {
  buildScan {
    termsOfServiceUrl = "https://gradle.com/terms-of-service"
    termsOfServiceAgree = "yes"
  }
}
