/*
 * Copyright (C) 2023-2024 Hedera Hashgraph, LLC
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

plugins {
    id("java")
    id("com.hedera.gradle.maven-publish")
}

// Publishing tasks are only enabled if we publish to the matching group.
// Otherwise, Nexus configuration and credentials do not fit.
//val publishingPackageGroup = providers.gradleProperty("publishingPackageGroup").getOrElse("")

tasks.withType<PublishToMavenRepository>().configureEach {
    // Not required since both common and cryptography modules are published under the same com.hedera prefix which
    // is the same configured Nexus profile on maven central.
    // enabled = publishingPackageGroup == "com.hedera.cryptography"
}

publishing {
    publications.named<MavenPublication>("maven") {
        // Explicitly set the package group to com.hedera.cryptography since the common module is published under
        // the same com.hedera Nexus profile.
        group = "com.hedera.cryptography"
        pom.description =
            "Swirlds is a software platform designed to build fully-distributed " +
                "applications that harness the power of the cloud without servers. " +
                "Now you can develop applications with fairness in decision making, " +
                "speed, trust and reliability, at a fraction of the cost of " +
                "traditional server-based platforms."

        pom.developers {
            developer {
                name = "Platform Base Team"
                email = "platform-base@swirldslabs.com"
                organization = "Hedera Hashgraph"
                organizationUrl = "https://www.hedera.com"
            }
            developer {
                name = "Platform Hashgraph Team"
                email = "platform-hashgraph@swirldslabs.com"
                organization = "Hedera Hashgraph"
                organizationUrl = "https://www.hedera.com"
            }
            developer {
                name = "Platform Data Team"
                email = "platform-data@swirldslabs.com"
                organization = "Hedera Hashgraph"
                organizationUrl = "https://www.hedera.com"
            }
            developer {
                name = "Release Engineering Team"
                email = "release-engineering@swirldslabs.com"
                organization = "Hedera Hashgraph"
                organizationUrl = "https://www.hedera.com"
            }
        }
    }
}
