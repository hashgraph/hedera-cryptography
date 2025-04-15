// SPDX-License-Identifier: Apache-2.0
import java.nio.file.Files
import org.hiero.gradle.tasks.CargoBuildTask

plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
}

cargo { libname = "raps" }

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("org.junit.jupiter.params")
    requires("com.hedera.cryptography.hints")
}

tasks.test { environment(mapOf("TSS_LIB_NUM_OF_CORES" to "10")) }

// TODO jjohannes: once finalized, move this into Gradle plugins
tasks.withType<CargoBuildTask> {
    doLast {
        val baseFolder = destinationDirectory.dir(toolchain.get().folder).get().asFile
        val destination = baseFolder.toPath().resolve("raps")
        val lib = baseFolder.listFiles().single()
        Files.createDirectory(destination)
        Files.move(lib.toPath(), destination.resolve(lib.name))
    }
}
