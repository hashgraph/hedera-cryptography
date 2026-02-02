// SPDX-License-Identifier: Apache-2.0
val junit5 = "6.0.2"
val mockito = "5.21.0"

dependencies.constraints {
    api("org.junit.jupiter:junit-jupiter-api:$junit5") { because("org.junit.jupiter.api") }
    api("org.junit.jupiter:junit-jupiter-engine:$junit5") { because("org.junit.jupiter.engine") }
    api("org.mockito:mockito-core:$mockito") { because("org.mockito") }
}
