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

plugins { id("com.hedera.gradle.settings") }

rootProject.name = "hedera-cryptography"

// "BOM" with versions of 3rd party dependencies
include("hedera-dependency-versions")

// Project to aggregate code coverage data for the whole repository into one report
include(":reports", "gradle/reports")
include("swirlds-nativesupport")
include("swirlds-crypto-pairings-api")
include("swirlds-crypto-pairings-signatures")
include("swirlds-crypto-altbn128")

fun include(name: String, path: String) {
    include(name)
    project(name).projectDir = File(rootDir, path)
}
