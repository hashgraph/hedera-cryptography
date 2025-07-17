// SPDX-License-Identifier: Apache-2.0
import java.net.URI
import org.gradle.kotlin.dsl.withType
import org.hiero.gradle.environment.EnvAccess
import org.hiero.gradle.extensions.CargoToolchain
import org.hiero.gradle.tasks.CargoBuildTask

// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
}

cargo { libname = "raps" }

tasks.withType<CargoBuildTask> {
    val goDstDir = layout.buildDirectory.dir("go-sdk").get()
    val goSdkDir = goDstDir.dir("go").asFile.absolutePath
    val hostOperatingSystem =
        System.getProperty("os.name").lowercase().let {
            if (it.contains("windows")) {
                "windows"
            } else if (it.contains("mac")) {
                "darwin"
            } else {
                "linux"
            }
        }

    doFirst {
        println("Installing Go SDK...")
        mkdir(goDstDir)
        val versions =
            EnvAccess.toolchainVersions(rootProject.layout.projectDirectory, providers, objects)
        val goVersion = versions.getting("go").get()

        val hostArchitecture =
            System.getProperty("os.arch").let {
                if (it.contains("x86_64")) {
                    "amd64"
                } else if (it.contains("aarch64")) {
                    "arm64"
                } else {
                    // There's "386" and "armv6l" at https://go.dev/dl/ .
                    it
                }
            }

        val goSrcFile = "go${goVersion}.${hostOperatingSystem}-${hostArchitecture}.tar.gz"
        val goSrcUri = "https://go.dev/dl/${goSrcFile}"
        val goSrcUrl = URI(goSrcUri).toURL()
        val goArchive = goDstDir.file("${goSrcFile}").asFile
        println("Downloading ${goSrcUri} to ${goArchive.absolutePath}")
        goArchive.writeBytes(goSrcUrl.readBytes())
        println("Extracting ${goArchive.absolutePath}")
        copy {
            from(tarTree(goArchive))
            into(goDstDir)
        }
        println("Go SDK has been installed at ${goSdkDir}")
    }

    doLast {
        // Define the binary name and the sources.
        // Assume the sources are already in the parent CargoBuildTask inputs,
        // so we don't need to add any additional inputs for our doLast{} actions here
        val executableName = "compressor"
        val srcPath = "src/main/rust/compressor"

        val srcDir = layout.projectDirectory.dir(srcPath)
        val outDir = layout.buildDirectory.dir("target/${toolchain.get().platform}").get()
        println(
            "Start building ${executableName} from " +
                srcDir.toString() +
                " to " +
                outDir.toString()
        )

        val includePath = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include"
        println("Using C include path: " + includePath)
        println("Using Go SDK path: " + goSdkDir)

        val cargoHome = rustInstallFolder.dir("cargo").get().asFile

        val timoutInMinutes = 15L
        val processBuilder =
            ProcessBuilder()
                .command(
                    File(cargoHome, "bin/cargo").absolutePath,
                    "build",
                    "--release",
                    "--target-dir",
                    outDir.toString(),
                )
                .directory(srcDir.asFile)
                .redirectErrorStream(true)
        // Note: these redirects don't work for some reason.... So we read and print the stdout
        // manually below...
        // .redirectOutput(ProcessBuilder.Redirect.INHERIT)
        // .redirectError(ProcessBuilder.Redirect.INHERIT)

        // Must add Go SDK bin/ to PATH as the first path because Rust simply calls "go".
        // Need to ensure we use the SDK we downloaded, rather than a random Go SDK installed on the
        // system.
        val pathSeparator = if (hostOperatingSystem.equals("windows")) ";" else ":"
        processBuilder
            .environment()
            .put(
                "PATH",
                "${goSdkDir}/bin" +
                    (if (processBuilder.environment().containsKey("PATH"))
                        pathSeparator + processBuilder.environment().get("PATH")
                    else ""),
            )
        processBuilder
            .environment()
            .putAll(
                mapOf(
                    "CPATH" to includePath,
                    "CARGO_HOME" to cargoHome.absolutePath,
                    "GOROOT" to goSdkDir,
                )
            )

        val process = processBuilder.start()

        val hasExited = process.waitFor(timoutInMinutes, TimeUnit.MINUTES)
        println("${executableName} build output:")
        while (true) {
            val c = process.inputStream.read()
            if (c == -1) break
            print(c.toChar())
        }
        if (!hasExited) {
            throw GradleException(
                "${executableName} build hasn't finished in " + timoutInMinutes + " minutes"
            )
        } else if (process.exitValue() != 0) {
            throw GradleException(
                "${executableName} build exited with non-zero exit code: " + process.exitValue()
            )
        } else {
            println("Finished building ${executableName}")
        }

        // Compute the destination path to add the executable to resources in JAR
        val baseFolder = javaPackage.get().replace('.', '/')
        val targetFolder = baseFolder + "/" + executableName + "/" + toolchain.get().folder
        val resourcesDir = destinationDirectory.dir(targetFolder)
        val buildsForWindows = toolchain.get() == CargoToolchain.x86Windows
        val fileExtension = if (buildsForWindows) ".exe" else ""
        val fullExecutableName = "${executableName}${fileExtension}"
        val fullExecutablePath = resourcesDir.get().file(fullExecutableName)
        // Note: the resourcesDir is already an output of the parent CargoBuildTask,
        // so we don't need to declare any additional outputs for our doLast{} actions here.

        println(
            "Copying ${executableName} to resources at ${fullExecutablePath.asFile.absolutePath}..."
        )
        copy {
            from(outDir.dir("release"))
            into(resourcesDir)

            include("${executableName}${fileExtension}")
        }
    }
}

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("org.junit.jupiter.params")
}

tasks.test { environment(mapOf("TSS_LIB_NUM_OF_CORES" to "10")) }
