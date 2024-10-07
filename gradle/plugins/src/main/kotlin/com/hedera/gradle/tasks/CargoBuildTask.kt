/*
 * Copyright (C) 2024 Hedera Hashgraph, LLC
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

package com.hedera.gradle.tasks

import com.hedera.gradle.extensions.CargoToolchain
import java.io.File
import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.internal.file.FileOperations
import org.gradle.api.logging.LogLevel
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations

@CacheableTask
abstract class CargoBuildTask : DefaultTask() {

    @get:Input abstract val libname: Property<String>

    @get:Input abstract val release: Property<Boolean>

    @get:Input abstract val toolchain: Property<CargoToolchain>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val cargoToml: RegularFileProperty

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.NAME_ONLY)
    abstract val sourcesDirectory: DirectoryProperty

    @get:OutputDirectory abstract val destinationDirectory: DirectoryProperty

    @get:Internal abstract val cargoCommand: Property<String>

    @get:Inject protected abstract val exec: ExecOperations

    @get:Inject protected abstract val files: FileOperations

    @TaskAction
    fun build() {
        installCargoZigbuild()
        buildForTarget()

        val profile = if (release.get()) "release" else "debug"
        val cargoOutputDir =
            File(cargoToml.get().asFile.parent, "target/${toolchain.get().target}/${profile}")

        files.copy {
            from(cargoOutputDir)
            into(destinationDirectory.dir(toolchain.get().folder))

            include("lib${libname.get()}.so")
            include("lib${libname.get()}.dylib")
            include("${libname.get()}.dll")
        }
    }

    private fun installCargoZigbuild() {
        exec.exec {
            workingDir = cargoToml.get().asFile.parentFile
            commandLine = listOf(cargoCommand.get(), "install", "--locked", "cargo-zigbuild")
        }
    }

    private fun buildForTarget() {
        exec.exec {
            workingDir = cargoToml.get().asFile.parentFile

            commandLine =
                listOf(cargoCommand.get(), "zigbuild", "--target=${toolchain.get().target}")

            if (release.get()) {
                args("--release")
            }
            if (logger.isEnabled(LogLevel.INFO)) {
                // For '--info' logging, turn on '--verbose'
                args("--verbose")
            }
        }
    }
}
