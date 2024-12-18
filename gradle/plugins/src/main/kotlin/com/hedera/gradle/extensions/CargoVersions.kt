package com.hedera.gradle.extensions

import org.gradle.api.Task
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input

interface CargoVersions : Task {
    @get:Input val rustVersion: Property<String>
    @get:Input val cargoZigbuildVersion: Property<String>
    @get:Input val zigVersion: Property<String>
    @get:Input val xwinVersion: Property<String>
}
