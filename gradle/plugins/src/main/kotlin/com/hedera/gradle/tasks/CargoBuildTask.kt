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

import com.hedera.gradle.extensions.Toolchain
import java.io.ByteArrayOutputStream
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
import org.gradle.api.tasks.Nested
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations

@CacheableTask
abstract class CargoBuildTask : DefaultTask() {

    @get:Input abstract val libname: Property<String>

    @get:Input abstract val profile: Property<String>

    @get:Input abstract val verbose: Property<Boolean>

    @get:Input @get:Optional abstract val rustupChannel: Property<String>

    @get:Input abstract val rustcCommand: Property<String>

    @get:Input abstract val cargoCommand: Property<String>

    @get:Nested abstract val toolchain: Property<Toolchain>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val cargoToml: RegularFileProperty

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.NAME_ONLY)
    abstract val sourcesDirectory: DirectoryProperty

    @get:OutputDirectory abstract val destinationDirectory: DirectoryProperty

    @get:Inject protected abstract val exec: ExecOperations

    @get:Inject protected abstract val files: FileOperations

    @TaskAction
    fun build() {
        val defaultTargetTriple = defaultTargetTriple(rustcCommand.get())
        buildProjectForTarget(defaultTargetTriple)

        val cargoOutputDir =
            File(
                cargoToml.get().asFile.parent,
                if (toolchain.get().target == defaultTargetTriple) {
                    "target/${profile.get()}"
                } else {
                    "target/${toolchain.get().target}/${profile.get()}"
                }
            )

        files.copy {
            from(cargoOutputDir)
            into(destinationDirectory.dir(toolchain.get().folder))

            include("lib${libname.get()}.so")
            include("lib${libname.get()}.dylib")
            include("${libname.get()}.dll")
        }
    }

    private fun buildProjectForTarget(defaultTargetTriple: String) {
        exec.exec {
            workingDir = cargoToml.get().asFile.parentFile
            val theCommandLine = mutableListOf(cargoCommand.get())

            if (rustupChannel.isPresent) {
                val hasPlusSign = rustupChannel.get().startsWith("+")
                val maybePlusSign = if (!hasPlusSign) "+" else ""
                theCommandLine.add(maybePlusSign + rustupChannel)
            }

            theCommandLine.add("build")

            // Respect `verbose` if it is set; otherwise, log if asked to
            // with `--info` or `--debug` from the command line.
            if (verbose.get() || logger.isEnabled(LogLevel.INFO)) {
                theCommandLine.add("--verbose")
            }

            if (profile.get() != "debug") {
                // Cargo is rigid: it accepts "--release" for release (and
                // nothing for dev).  This is a cheap way of allowing only
                // two values.
                theCommandLine.add("--${profile.get()}")
            }
            if (toolchain.get().target != defaultTargetTriple) {
                // Only providing --target for the non-default targets means desktop builds
                // can share the build cache with `cargo build`/`cargo test`/etc invocations,
                // instead of requiring a large amount of redundant work.
                theCommandLine.add("--target=${toolchain.get().target}")
            }
            commandLine = theCommandLine
        }
    }

    private fun defaultTargetTriple(rustc: String): String {
        val stdout = ByteArrayOutputStream()
        exec.exec {
            standardOutput = stdout
            commandLine = listOf(rustc, "--version", "--verbose")
        }
        val output = stdout.toString()

        // The `rustc --version --verbose` output contains a number of lines like `key: value`.
        // We're only interested in `host: `, which corresponds to the default target triple.
        val triplePrefix = "host: "

        val triple =
            output
                .split("\n")
                .find { it.startsWith(triplePrefix) }
                ?.substring(triplePrefix.length)
                ?.trim()

        if (triple == null) {
            throw RuntimeException("Failed to parse `rustc -Vv` output!")
        } else {
            logger.info("Default rust target triple: $triple")
        }
        return triple
    }
}
