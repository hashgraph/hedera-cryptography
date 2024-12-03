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
import com.hedera.gradle.tasks.RustToolchainInstallTask
import java.util.Properties
import javax.inject.Inject
import org.gradle.api.Project
import org.gradle.api.file.ProjectLayout
import org.gradle.api.provider.Property
import org.gradle.api.provider.ProviderFactory
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.api.tasks.TaskContainer
import org.gradle.kotlin.dsl.named
import org.gradle.kotlin.dsl.register

@Suppress("LeakingThis")
abstract class CargoExtension {
    abstract val cargoBin: Property<String>
    abstract val libname: Property<String>
    abstract val release: Property<Boolean>

    @get:Inject protected abstract val project: Project

    @get:Inject protected abstract val layout: ProjectLayout

    @get:Inject protected abstract val tasks: TaskContainer

    @get:Inject protected abstract val providers: ProviderFactory

    @get:Inject protected abstract val sourceSets: SourceSetContainer

    init {
        cargoBin.convention(System.getProperty("user.home") + "/.cargo/bin")
        libname.convention(project.name)
        release.convention(true)

        @Suppress("UnstableApiUsage")
        val versionsFile =
            project.isolated.rootProject.projectDirectory.file(
                "gradle/toolchain-versions.properties"
            )
        val versions = Properties()
        versions.load(
            providers
                .fileContents(versionsFile)
                .asText
                .orElse(
                    providers.provider {
                        throw RuntimeException("${versionsFile.asFile} does not exist")
                    }
                )
                .get()
                .reader()
        )

        // Rust toolchain installation
        tasks.register<RustToolchainInstallTask>("installRustToolchain") {
            // Track host system as input as the task output differs between operating systems
            hostOperatingSystem.set(readHostOperatingSystem())
            hostArchitecture.set(System.getProperty("os.arch"))

            rustVersion.convention(versions.getValue("rust") as String)
            cargoZigbuildVersion.convention(versions.getValue("cargo-zigbuild") as String)
            zigVersion.convention(versions.getValue("zig") as String)
            xwinVersion.convention(versions.getValue("xwin") as String)

            toolchains.convention(CargoToolchain.values().asList())
            destinationDirectory.convention(layout.buildDirectory.dir("rust-toolchains"))
        }

        // Lifecycle task to only do all carg build tasks (mainly for testing)
        project.tasks.register("cargoBuild") {
            group = "rust"
            description = "Build library (all targets)"
        }
    }

    private fun readHostOperatingSystem() =
        System.getProperty("os.name").lowercase().let {
            if (it.contains("windows")) {
                "windows"
            } else if (it.contains("mac")) {
                "macos"
            } else {
                "linux"
            }
        }

    fun targets(vararg targets: CargoToolchain) {
        val installTask = tasks.named<RustToolchainInstallTask>("installRustToolchain")
        targets.forEach { target ->
            val targetBuildTask =
                tasks.register<CargoBuildTask>(
                    "cargoBuild${target.name.replaceFirstChar(Char::titlecase)}"
                ) {
                    group = "rust"
                    description = "Build library ($target)"
                    toolchain.convention(target)
                    sourcesDirectory.convention(layout.projectDirectory.dir("src/main/rust"))
                    destinationDirectory.convention(
                        layout.buildDirectory.dir("rustJniLibs/${target.platform}")
                    )

                    this.cargoToml.convention(layout.projectDirectory.file("Cargo.toml"))
                    this.libname.convention(this@CargoExtension.libname)
                    this.release.convention(this@CargoExtension.release)
                    this.rustInstallFolder.convention(
                        installTask.flatMap { it.destinationDirectory }
                    )
                }

            tasks.named("cargoBuild") { dependsOn(targetBuildTask) }
            sourceSets.getByName("main").resources.srcDir(targetBuildTask)
        }
    }
}
