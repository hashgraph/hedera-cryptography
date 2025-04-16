// SPDX-License-Identifier: Apache-2.0
import java.nio.file.Files
import java.nio.file.StandardCopyOption
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
        val originalPath = toolchain.get().folder
        val adjustedPath = originalPath.replace("software/", "com/hedera/nativelib/raps/")
        val originalFile =
            destinationDirectory.dir(originalPath).get().asFile.listFiles()!!.single().toPath()
        val adjustedFile =
            destinationDirectory
                .dir(adjustedPath)
                .get()
                .asFile
                .toPath()
                .resolve(originalFile.fileName)
        Files.createDirectories(adjustedFile.parent)
        Files.move(originalFile, adjustedFile, StandardCopyOption.REPLACE_EXISTING)
        destinationDirectory.dir("software").get().asFile.delete()
    }
}
