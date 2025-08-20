// SPDX-License-Identifier: Apache-2.0
import java.net.URI
import org.gradle.api.internal.file.FileOperations
import org.gradle.kotlin.dsl.withType
import org.hiero.gradle.environment.EnvAccess
import org.hiero.gradle.tasks.CargoBuildTask

plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
    id("DownloadGroth16ArtifactTask")
}

cargo { libname = "raps" }

interface Injected {
    @get:Inject val files: FileOperations
}

// Build the compressor executable as a custom `cargo build` run with a non-trivial configuration
// in order to support the cross-compilation of the inner Go library that sp1 builds internally:
tasks.withType<CargoBuildTask> {
    // Utility for file operations
    val injected = project.objects.newInstance<Injected>()

    // Add the cargo build task platform to the GoSDK path so that parallel downloads don't clash:
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

    val versions =
        EnvAccess.toolchainVersions(rootProject.layout.projectDirectory, providers, objects)

    doFirst {
        println("Installing Go SDK...")
        injected.files.mkdir(goDstDir)

        val goVersion = versions.getting("go").get()

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
        // This helps setup GOOS/GOARCH below:
        val osArchArray = toolchain.get().folder.split("/")

        println(
            "Start building ${executableName} from " +
                srcDir.toString() +
                " to " +
                outDir.toString()
        )

        println("Using Go SDK path: " + goSdkDir)

        val cargoHome = rustInstallFolder.dir("cargo").get().asFile
        val rustupHome = rustInstallFolder.dir("rustup").get().asFile.absolutePath

        // Sanitize the target. The toolchain may look like "aarch64-unknown-linux-gnu.2.18",
        // but the ".2.18" part is "wrong" - as in, the toolchain doesn't know about such a target.
        // Chop it off:
        val periodIndex = toolchain.get().target.indexOf('.')
        val origTarget =
            if (periodIndex == -1) toolchain.get().target
            else toolchain.get().target.substring(0, periodIndex)
        // This is a bit of a hack, but the outer CargoBuildTask builds for x86_64-pc-windows-msvc.
        // So far we were unable to build the compressor for the msvc env, so we build it for the
        // gnu env instead. This executable is separate from the raps library, so a different env
        // doesn't really matter:
        val target = if (origTarget.contains("windows")) "x86_64-pc-windows-gnu" else origTarget

        println(
            "Building ${executableName} for target: ${target} (original ${toolchain.get().target}) on host: $hostOperatingSystem-$hostArchitecture"
        )

        val timeoutInMinutes = 20L
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
        // Note: these redirects don't work for some reason. So we read the stdout and print it
        // manually below.
        // .redirectOutput(ProcessBuilder.Redirect.INHERIT)
        // .redirectError(ProcessBuilder.Redirect.INHERIT)

        // Must add Go SDK bin/ to PATH as the first path because Rust simply calls "go".
        // Need to ensure we use the SDK we downloaded, rather than a random Go SDK installed on the
        // system. Also add our toolchain's Rust/Cargo bin/ to PATH as well:
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

        // Also set SDK homes and Go target:
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

        // Generate more output for the inner Go build. It's not too very noisy in the logs,
        // but it helps spot and debug build issues for this most complex native build here:
        processBuilder.environment().put("GOFLAGS", "-v -x")

        // Set the Cargo target:
        processBuilder.environment().put("CARGO_BUILD_TARGET", target)

        // ----------------------------------------------------------------
        // Configuration specific to various host/target platforms follows:
        // ----------------------------------------------------------------
        // Note that we don't necessarily support random host/target pairs.
        // We can build for all target platforms in GitHub.
        // We can also build native Mac binaries on a local Mac (tested on aarch64 host only.)
        // Other host/target combination may or (likely) may not work.
        // If we need to support them, then we'll have to add more complexity to the
        // configurations below. For local builds, simply exclude platforms that are not needed,
        // e.g.:
        //
        // gradle build -x cargoBuildX86Windows -x cargoBuildX86Darwin -x cargoBuildX86Linux -x
        // cargoBuildAarch64Linux
        //
        // Ideally, we should modify our Gradle scripts so that by default, they only build for the
        // host target. There's no need to spend time or set up a complex environment to build for
        // other targets because the produced binaries are unusable on the host directly, and the
        // build would still likely differ from what's happening in GitHub anyway. So a local
        // success won't guarantee a GitHub success.

        if (hostOperatingSystem == "darwin") {
            println(
                "Configuring cross-compilation for ${target} on $hostOperatingSystem-$hostArchitecture..."
            )

            val includePath =
                StringBuilder()
                    .apply {
                        println("Determining include path...")
                        val xcrunTimeoutInMinutes = 1L
                        val xcrunProcessBuilder =
                            ProcessBuilder()
                                .command("xcrun", "--show-sdk-path")
                                .redirectErrorStream(true)
                        val process = xcrunProcessBuilder.start()
                        val hasExited = process.waitFor(xcrunTimeoutInMinutes, TimeUnit.MINUTES)

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
                                    xcrunTimeoutInMinutes +
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

            println("Setting CPATH to: " + includePath)
            processBuilder.environment().put("CPATH", includePath)
        }

        if (hostOperatingSystem == "linux") {
            // Assume we're running on linux-x86_64 natively because that's what we do in GitHub.
            // More complexity would be required below to support building natively on
            // linux-aarch64, or cross-building for linux-x86_64 target on a linux-aarch64 host:

            if (target.contains("linux") && target.startsWith("aarch64-")) {
                println(
                    "Configuring cross-compilation for ${target} on $hostOperatingSystem-$hostArchitecture..."
                )

                processBuilder
                    .environment()
                    .put("SP1_GNARK_FFI_GO_ENVS", "CC=aarch64-linux-gnu-gcc")
                processBuilder
                    .environment()
                    .put("CARGO_TARGET_AARCH64_LINUX_GNU_LINKER", "aarch64-linux-gnu-gcc")
                processBuilder
                    .environment()
                    .put("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", "aarch64-linux-gnu-gcc")
            }
        }

        if (target.contains("windows")) {
            // Assume we're running on linux-x86_64 natively because that's what we do in GitHub.
            // It's possible to build for windows on mac with:
            //
            // SP1_GNARK_FFI_SKIP_MAC_FRAMEWORKS=true
            // BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/Cellar/mingw-w64/13.0.0/toolchain-x86_64/x86_64-w64-mingw32/include"
            // CARGO_BUILD_TARGET=x86_64-pc-windows-gnu
            // GOOS=windows
            // GOARCH=amd64
            // GOFLAGS="-v -x"
            // SP1_GNARK_FFI_GO_ENVS="CC=x86_64-w64-mingw32-gcc;CPATH=/opt/homebrew/Cellar/mingw-w64/13.0.0/toolchain-x86_64/x86_64-w64-mingw32/include"
            // CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
            // CFLAGS_x86_64_pc_windows_gnu="-I/opt/homebrew/Cellar/mingw-w64/13.0.0/toolchain-x86_64/x86_64-w64-mingw32/include"
            // cargo build --release  --target=x86_64-pc-windows-gnu --target-dir ...
            //
            // However, we don't support this here for now because this requires installing mingw
            // from brew.
            // Similarly, we don't support native windows builds on windows hosts currently.

            println(
                "Configuring cross-compilation for ${target} on $hostOperatingSystem-$hostArchitecture..."
            )

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
            // Just in case we ever use parts of this setup on a Mac:
            processBuilder.environment().put("SP1_GNARK_FFI_SKIP_MAC_FRAMEWORKS", "true")
        }

        // ----------------------------------------------------------------
        // Run the actual build:
        // ----------------------------------------------------------------
        println("Build environment:")
        processBuilder.environment().forEach { key, value -> println("$key: $value") }
        println("Build command with timeout of $timeoutInMinutes minutes:")
        println(processBuilder.command().joinToString(" "))

        val process = processBuilder.start()

        val hasExited = process.waitFor(timeoutInMinutes, TimeUnit.MINUTES)
        println("${executableName} build output:")
        while (true) {
            val c = process.inputStream.read()
            if (c == -1) break
            print(c.toChar())
        }
        if (!hasExited) {
            throw GradleException(
                "${executableName} build hasn't finished in " + timeoutInMinutes + " minutes"
            )
        } else if (process.exitValue() != 0) {
            throw GradleException(
                "${executableName} build exited with non-zero exit code: " + process.exitValue()
            )
        } else {
            println("Finished building ${executableName}")
        }

        // ----------------------------------------------------------------
        // Add the built executable to the JAR:
        // ----------------------------------------------------------------
        val baseFolder = javaPackage.get().replace('.', '/')
        val targetFolder = baseFolder + "/" + executableName + "/" + toolchain.get().folder
        val resourcesDir = destinationDirectory.dir(targetFolder)

        // sync won't create the directory for us, but it won't fail the operation either,
        // making it a silent failure. So we must create the destination directory manually:
        injected.files.mkdir(resourcesDir)

        val buildsForWindows = target.contains("windows")
        val fileExtension = if (buildsForWindows) ".exe" else ""
        val fullExecutableName = "${executableName}${fileExtension}"
        val fullExecutablePath = resourcesDir.get().file(fullExecutableName)
        // Note: the resourcesDir is already an output of the parent CargoBuildTask,
        // so we don't need to declare any additional outputs for our doLast{} actions here.

        val binSrcDir = outDir.dir(target).dir("release")

        println(
            "Copying ${fullExecutableName} from ${binSrcDir.asFile.absolutePath} to ${fullExecutablePath.asFile.absolutePath}"
        )
        injected.files.sync {
            from(binSrcDir)
            into(resourcesDir)

            include("${fullExecutableName}")
        }
    }
}

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("org.junit.jupiter.params")
}

tasks.test {
    dependsOn("downloadGroth16ArtifactTask")
    environment(
        mapOf(
            // For the TSS lib:
            "TSS_LIB_NUM_OF_CORES" to "10",
            // For the compressor that runs Go:
            "GOMAXPROCS" to "10",
            // Path to Groth16 artifacts:
            "SP1_GROTH16_CIRCUIT_PATH" to
                (tasks.named("downloadGroth16ArtifactTask").get().property("groth16Dir")
                        as DirectoryProperty)
                    .get()
                    .asFile
                    .absolutePath,
        )
    )
}
