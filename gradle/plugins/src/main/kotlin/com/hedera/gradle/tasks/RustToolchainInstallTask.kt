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
import java.net.URI
import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.file.ArchiveOperations
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.internal.file.FileOperations
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations

@CacheableTask
abstract class RustToolchainInstallTask : DefaultTask() {

    @get:Input abstract val rustVersion: Property<String>
    @get:Input abstract val cargoZigbuildVersion: Property<String>
    @get:Input abstract val zigVersion: Property<String>
    @get:Input abstract val xwinVersion: Property<String>

    @get:Input abstract val hostOperatingSystem: Property<String>
    @get:Input abstract val hostArchitecture: Property<String>

    @get:Input abstract val toolchains: ListProperty<CargoToolchain>

    @get:OutputDirectory abstract val destinationDirectory: DirectoryProperty

    @get:Inject protected abstract val exec: ExecOperations

    @get:Inject protected abstract val files: FileOperations

    @get:Inject protected abstract val archives: ArchiveOperations

    @TaskAction
    fun install() {
        destinationDirectory.get().asFile.listFiles()?.forEach { files.delete(it) }
        installZig()
        installRust()
    }

    private fun installZig() {
        val isWindows = hostOperatingSystem.get() == "windows"
        val arch = hostArchitecture.get().let { if (it == "amd64") "x86_64" else it }
        val zigArchiveName =
            "zig-${hostOperatingSystem.get()}-$arch-${zigVersion.get()}"
        val fileExtension = if (isWindows) "zip" else "tar.xz"

        val url =
            URI("https://ziglang.org/download/${zigVersion.get()}/$zigArchiveName.$fileExtension")
                .toURL()
        val zigArchive = destinationDirectory.file("$zigArchiveName.$fileExtension").get().asFile
        zigArchive.writeBytes(url.readBytes())

        if (isWindows) {
            files.copy {
                from(archives.tarTree(zigArchive))
                into(destinationDirectory)
            }
        } else {
            // Use command line to un-tar as it is unfortunately not supported by ArchiveOperations
            // https://github.com/gradle/gradle/issues/15065

            exec.exec {
                commandLine(
                    "tar",
                    "xJf",
                    zigArchive.absolutePath,
                    "-C",
                    destinationDirectory.get().asFile.absolutePath
                )
            }
        }

        destinationDirectory
            .dir(zigArchiveName)
            .get()
            .asFile
            .renameTo(destinationDirectory.dir("zig").get().asFile)

        files.delete(zigArchive)
    }

    private fun installRust() {
        val url = URI("https://sh.rustup.rs").toURL()
        val rustupInstall = destinationDirectory.file("rustup-install.sh").get().asFile
        rustupInstall.writeText(url.readText())
        rustupInstall.setExecutable(true)

        val cargoCmd = destinationDirectory.dir("cargo/bin/cargo").get().asFile.absolutePath
        val xwinCmd = destinationDirectory.dir("cargo/bin/xwin").get().asFile.absolutePath
        val xwinFolder = destinationDirectory.dir("xwin").get().asFile.absolutePath

        val targets =
            toolchains.get().flatMap {
                listOf("-t", it.target.replaceAfter(".", "").replace(".", ""))
            }

        execute(
            listOf(
                rustupInstall.absolutePath,
                "-y",
                "--profile=minimal",
                "--default-toolchain=${rustVersion.get()}"
            ) + targets
        )
        execute(
            listOf(
                cargoCmd,
                "+${rustVersion.get()}",
                "install",
                "--locked",
                "--ignore-rust-version",
                "--profile=release",
                "cargo-zigbuild@${cargoZigbuildVersion.get()}"
            )
        )
        execute(
            listOf(
                cargoCmd,
                "+${rustVersion.get()}",
                "install",
                "--locked",
                "--profile=release",
                "xwin@${xwinVersion.get()}"
            )
        )
        execute(listOf(xwinCmd, "--accept-license", "splat", "--output", xwinFolder))

        files.delete(rustupInstall)
    }

    private fun execute(cmd: List<String>) {
        val rustupFolder = destinationDirectory.dir("rustup").get().asFile.absolutePath
        val cargoFolder = destinationDirectory.dir("cargo").get().asFile.absolutePath
        exec.exec {
            environment("RUSTUP_HOME", rustupFolder)
            environment("CARGO_HOME", cargoFolder)
            // https://github.com/Jake-Shadle/xwin/issues/141#issuecomment-2416864318
            environment("RAYON_NUM_THREADS", "1")
            commandLine = cmd
        }
    }
}
