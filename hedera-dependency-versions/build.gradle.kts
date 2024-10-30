/*
 * Copyright (C) 2023 Hedera Hashgraph, LLC
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

// Note: Need to maintain 3rd party versions between hedera-cryptography and hedera-services repository

plugins {
    id("com.hedera.gradle.versions")
}

// define versions for gradle to grab dependencies
dependencies.constraints {
    api("com.google.guava:guava:31.1-jre") {
        because("com.google.common")
    }
    api("com.github.spotbugs:spotbugs-annotations:4.7.3") {
        because("com.github.spotbugs.annotations")
    }
    api("io.grpc:grpc-protobuf:1.65.1") {
        because("io.grpc.protobuf")
    }
    api("com.google.protobuf:protobuf-java:3.21.7") {
        because("com.google.protobuf")
    }
    api("com.google.protobuf:protobuf-java-util:3.21.7") {
        because("com.google.protobuf.util")
    }
    api("org.mockito:mockito-core:5.8.0") {
        because("org.mockito")
    }
    api("org.mockito:mockito-junit-jupiter:5.8.0") {
        because("org.mockito.junit.jupiter")
    }
    api("org.bouncycastle:bcprov-jdk18on:1.78.1") {
        because("org.bouncycastle.provider")
    }
}
