// SPDX-License-Identifier: Apache-2.0
import java.net.URI
import org.gradle.api.internal.file.FileOperations
import org.gradle.kotlin.dsl.withType
import org.hiero.gradle.environment.EnvAccess
import org.hiero.gradle.tasks.CargoBuildTask

// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
}

cargo { libname = "raps" }

interface Injected {
    @get:Inject val files: FileOperations
}

tasks.withType<CargoBuildTask> {
    val injected = project.objects.newInstance<Injected>()

    // Add the cargo build task platform so that parallel downloads don't clash:
    val goDstDir = layout.buildDirectory.dir("go-sdk/${toolchain.get().platform}").get()
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
    val versions =
        EnvAccess.toolchainVersions(rootProject.layout.projectDirectory, providers, objects)

    doFirst {
        println("Installing Go SDK...")
        injected.files.mkdir(goDstDir)

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
        injected.files.sync {
            from(injected.files.tarTree(goArchive))
            into(goDstDir)
        }
        println("Go SDK has been installed at ${goSdkDir}")
    }

    // Define the binary name and the sources.
    // Assume the sources are already in the parent CargoBuildTask inputs,
    // so we don't need to add any additional inputs for our doLast{} actions here
    val executableName = "compressor"
    val srcPath = "src/main/rust/compressor"

    val srcDir = layout.projectDirectory.dir(srcPath)
    val outDir = layout.buildDirectory.dir("target/${toolchain.get().platform}").get()

    doLast {
        val osArchArray = toolchain.get().folder.split("/")

        println(
            "Start building ${executableName} from " +
                srcDir.toString() +
                " to " +
                outDir.toString()
        )

        println("Using Go SDK path: " + goSdkDir)

        val includePath =
            if (hostOperatingSystem != "darwin") null
            else
                StringBuilder()
                    .apply {
                        println("Determining include path...")
                        val timoutInMinutes = 1L
                        val processBuilder =
                            ProcessBuilder()
                                .command("xcrun", "--show-sdk-path")
                                .redirectErrorStream(true)
                        val process = processBuilder.start()
                        val hasExited = process.waitFor(timoutInMinutes, TimeUnit.MINUTES)

                        while (true) {
                            val c = process.inputStream.read()
                            if (c == -1) break
                            if (c < 20) continue // skip control characters like new line
                            append(c.toChar())
                        }

                        if (!hasExited) {
                            println(toString())
                            throw GradleException(
                                "Determining include path hasn't finished in " +
                                    timoutInMinutes +
                                    " minutes"
                            )
                        } else if (process.exitValue() != 0) {
                            println(toString())
                            throw GradleException(
                                "Determining include path exited with non-zero exit code: " +
                                    process.exitValue()
                            )
                        }

                        append("/usr/include")
                    }
                    .toString()

        val cargoHome = rustInstallFolder.dir("cargo").get().asFile
        val rustupHome = rustInstallFolder.dir("rustup").get().asFile.absolutePath

        // Sanitize the target. The toolchain may look like "aarch64-unknown-linux-gnu.2.18",
        // but the ".2.18" part is "wrong" - as in, the toolchain doesn't know about such a target.
        // Chop it off:
        val periodIndex = toolchain.get().target.indexOf('.')
        val origTarget =
            if (periodIndex == -1) toolchain.get().target
            else toolchain.get().target.substring(0, periodIndex)
        val target = if (origTarget.contains("windows")) "x86_64-pc-windows-gnu" else origTarget
        println("Building for target: ${target} (original ${toolchain.get().target})")

        val timoutInMinutes = 7L
        val processBuilder =
            ProcessBuilder()
                .command(
                    File(cargoHome, "bin/cargo").absolutePath,
                    "build",
                    "--release",
                    "--target=${target}",
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
                    pathSeparator +
                    "${rustupHome}/bin" +
                    pathSeparator +
                    "${cargoHome.absolutePath}/bin" +
                    (if (processBuilder.environment().containsKey("PATH"))
                        pathSeparator + processBuilder.environment().get("PATH")
                    else ""),
            )
        processBuilder
            .environment()
            .putAll(
                mapOf(
                    "CARGO_HOME" to cargoHome.absolutePath,
                    "RUSTUP_HOME" to rustupHome,
                    "GOROOT" to goSdkDir,
                    "GOOS" to osArchArray[0],
                    "GOARCH" to osArchArray[1],
                )
            )

        if (hostOperatingSystem == "darwin") {
            println("Using C include path: " + includePath)
            processBuilder.environment().put("CPATH", includePath)
        }

        if (hostOperatingSystem == "linux") {
            if (target.contains("linux")) {
                if (target.startsWith("aarch64-")) {
                    println("Configuring cross-compilation for ${target}...")

                    processBuilder.environment().put("CARGO_BUILD_TARGET", target)
                    processBuilder
                        .environment()
                        .put("SP1_GNARK_FFI_GO_ENVS", "CC=aarch64-linux-gnu-gcc")
                    processBuilder
                        .environment()
                        .put("CARGO_TARGET_AARCH64_LINUX_GNU_LINKER", "aarch64-linux-gnu-gcc")
                    processBuilder
                        .environment()
                        .put(
                            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER",
                            "aarch64-linux-gnu-gcc",
                        )
                    processBuilder.environment().put("GOFLAGS", "-v -x")
                }
            }
        }

        if (target.contains("windows")) {
            println("Configuring cross-compilation for ${target}...")

            processBuilder.environment().put("CARGO_BUILD_TARGET", target)
            processBuilder.environment().put("CC_x86_64_pc_windows_gnu", "x86_64-w64-mingw32-gcc")
            processBuilder
                .environment()
                .put("CFLAGS_x86_64_pc_windows_gnu", "-I/usr/x86_64-w64-mingw32/include")
            processBuilder
                .environment()
                .put("BINDGEN_EXTRA_CLANG_ARGS", "-I/usr/x86_64-w64-mingw32/include")
            processBuilder
                .environment()
                .put(
                    "SP1_GNARK_FFI_GO_ENVS",
                    "CC=x86_64-w64-mingw32-gcc;CPATH=/usr/x86_64-w64-mingw32/include",
                )
            processBuilder.environment().put("SP1_GNARK_FFI_SKIP_MAC_FRAMEWORKS", "true")
            processBuilder.environment().put("GOFLAGS", "-v -x")
        }

        println("Build environment:")
        processBuilder.environment().forEach { key, value -> println("$key: $value") }
        println("Build command:")
        println(processBuilder.command().joinToString(" "))

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
        val buildsForWindows = target.contains("windows")
        val fileExtension = if (buildsForWindows) ".exe" else ""
        val fullExecutableName = "${executableName}${fileExtension}"
        val fullExecutablePath = resourcesDir.get().file(fullExecutableName)
        // Note: the resourcesDir is already an output of the parent CargoBuildTask,
        // so we don't need to declare any additional outputs for our doLast{} actions here.

        println("Copying ${executableName} to ${fullExecutablePath.asFile.absolutePath}")
        injected.files.sync {
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
