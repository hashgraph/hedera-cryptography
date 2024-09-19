package com.hedera.gradle.rust

import java.io.File
import java.util.*
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.configurationcache.extensions.capitalized

const val RUST_TASK_GROUP = "rust"

enum class ToolchainType {
    DESKTOP,
}

// See https://forge.rust-lang.org/platform-support.html.
val toolchains =
    listOf(
        Toolchain(
            "linux-x86-64",
            ToolchainType.DESKTOP,
            "x86_64-unknown-linux-gnu",
            "<compilerTriple>",
            "<binutilsTriple>",
            "desktop/linux-x86-64"
        ),
        // This should eventually go away: the darwin-x86-64 target will supersede it.
        // https://github.com/mozilla/rust-android-gradle/issues/77
        Toolchain(
            "darwin",
            ToolchainType.DESKTOP,
            "x86_64-apple-darwin",
            "<compilerTriple>",
            "<binutilsTriple>",
            "desktop/darwin"
        ),
        Toolchain(
            "darwin-x86-64",
            ToolchainType.DESKTOP,
            "x86_64-apple-darwin",
            "<compilerTriple>",
            "<binutilsTriple>",
            "desktop/darwin-x86-64"
        ),
        Toolchain(
            "darwin-aarch64",
            ToolchainType.DESKTOP,
            "aarch64-apple-darwin",
            "<compilerTriple>",
            "<binutilsTriple>",
            "desktop/darwin-aarch64"
        ),
        Toolchain(
            "win32-x86-64-msvc",
            ToolchainType.DESKTOP,
            "x86_64-pc-windows-msvc",
            "<compilerTriple>",
            "<binutilsTriple>",
            "desktop/win32-x86-64"
        ),
        Toolchain(
            "win32-x86-64-gnu",
            ToolchainType.DESKTOP,
            "x86_64-pc-windows-gnu",
            "<compilerTriple>",
            "<binutilsTriple>",
            "desktop/win32-x86-64"
        ),
    )

data class Toolchain(
    val platform: String,
    val type: ToolchainType,
    val target: String,
    val compilerTriple: String,
    val binutilsTriple: String,
    val folder: String
)

@Suppress("unused")
abstract class RustJvmPlugin : Plugin<Project> {
    internal lateinit var cargoExtension: CargoExtension

    override fun apply(project: Project) {
        with(project) {
            cargoExtension = extensions.create("cargo", CargoExtension::class.java)
            afterEvaluate { configurePlugin(this) }
        }
    }

    private fun configurePlugin(project: Project) =
        with(project) {
            val main = extensions.getByType(SourceSetContainer::class.java).getByName("main")

            cargoExtension.localProperties = Properties()

            val localPropertiesFile = File(project.rootDir, "local.properties")
            if (localPropertiesFile.exists()) {
                cargoExtension.localProperties.load(localPropertiesFile.inputStream())
            }

            if (cargoExtension.module == null) {
                throw GradleException("module cannot be null")
            }

            if (cargoExtension.libname == null) {
                throw GradleException("libname cannot be null")
            }

            // Allow to set targets, including per-project, in local.properties.
            val localTargets: String? =
                cargoExtension.localProperties.getProperty("rust.targets.${project.name}")
                    ?: cargoExtension.localProperties.getProperty("rust.targets")
            if (localTargets != null) {
                cargoExtension.targets = localTargets.split(',').map { it.trim() }
            }

            if (cargoExtension.targets == null) {
                throw GradleException("targets cannot be null")
            }

            val buildTask =
                tasks.maybeCreate("cargoBuild", DefaultTask::class.java).apply {
                    group = RUST_TASK_GROUP
                    description = "Build library (all targets)"
                }

            cargoExtension.targets!!.forEach { target ->
                val theToolchain = toolchains.find { it.platform == target }
                if (theToolchain == null) {
                    throw GradleException(
                        "Target ${target} is not recognized (recognized targets: ${toolchains.map { it.platform }.sorted()}).  Check `local.properties` and `build.gradle`."
                    )
                }

                val targetBuildTask =
                    tasks
                        .maybeCreate(
                            "cargoBuild${target.capitalized()}",
                            CargoBuildTask::class.java
                        )
                        .apply {
                            group = RUST_TASK_GROUP
                            description = "Build library ($target)"
                            toolchain = theToolchain
                        }

                buildTask.dependsOn(targetBuildTask)

                // TODO task should have output
                main.resources.srcDir(File("$buildDir/rustJniLibs/desktop"))
            }
        }
}
