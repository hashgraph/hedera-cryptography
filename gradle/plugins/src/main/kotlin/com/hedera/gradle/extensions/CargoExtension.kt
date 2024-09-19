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

package com.hedera.gradle.extensions

import com.hedera.gradle.tasks.CargoBuildTask
import javax.inject.Inject
import org.gradle.api.GradleException
import org.gradle.api.file.ProjectLayout
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.api.tasks.TaskContainer
import org.gradle.kotlin.dsl.register

// See https://forge.rust-lang.org/platform-support.html.
val toolchains =
    listOf(
        Toolchain("linux-x86-64", "x86_64-unknown-linux-gnu", "software/linux/amd64"),
        Toolchain("linux-aarch64", "aarch64-unknown-linux-gnu", "software/linux/arm64"),
        Toolchain("darwin-x86-64", "x86_64-apple-darwin", "software/darwin/amd64"),
        Toolchain("darwin-aarch64", "aarch64-apple-darwin", "software/darwin/arm64"),
        Toolchain("win32-x86-64-msvc", "x86_64-pc-windows-msvc", "software/windows/amd64")
    )

data class Toolchain(
    @get:Input val platform: String,
    @get:Input val target: String,
    @get:Input val folder: String
)

abstract class CargoExtension {
    abstract val cargoCommand: Property<String>
    abstract val rustcCommand: Property<String>
    abstract val rustupChannel: Property<String>
    abstract val libname: Property<String>
    abstract val profile: Property<String>
    abstract val verbose: Property<Boolean>

    @get:Inject protected abstract val layout: ProjectLayout

    @get:Inject protected abstract val tasks: TaskContainer

    @get:Inject protected abstract val sourceSets: SourceSetContainer

    fun targets(vararg targetNames: String) {
        targetNames.forEach { target ->
            val theToolchain = toolchains.find { it.platform == target }
            if (theToolchain == null) {
                throw GradleException(
                    "Target $target is not recognized (recognized targets: ${toolchains.map { it.platform }.sorted()})."
                )
            }

            val targetBuildTask =
                tasks.register<CargoBuildTask>(
                    "cargoBuild${target.replaceFirstChar(Char::titlecase)}"
                ) {
                    group = "rust"
                    description = "Build library ($target)"
                    toolchain.set(theToolchain)
                    sourcesDirectory.set(layout.projectDirectory.dir("src/main/rust"))
                    destinationDirectory.set(
                        layout.buildDirectory.dir("rustJniLibs/${theToolchain.platform}")
                    )

                    cargoToml.set(layout.projectDirectory.file("Cargo.toml"))
                    cargoCommand.set(this@CargoExtension.cargoCommand)
                    rustcCommand.set(this@CargoExtension.rustcCommand)
                    libname.set(this@CargoExtension.libname)
                    profile.set(this@CargoExtension.profile)
                    verbose.set(this@CargoExtension.verbose)
                    rustupChannel.set(this@CargoExtension.rustupChannel)
                }

            tasks.named("cargoBuild") { dependsOn(targetBuildTask) }
            sourceSets.getByName("main").resources.srcDir(targetBuildTask)
        }
    }
}
