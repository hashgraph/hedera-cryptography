// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.application")
    id("org.hiero.gradle.feature.shadow")
    id("org.gradlex.java-module-packaging") version "1.2"
}

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("org.junit.jupiter.params")
    requires("org.mockito")
    requires("org.mockito.junit.jupiter")
}

application.mainClass = "com.hedera.cryptography.ceremony.Orchestrator"

javaModulePackaging {
    target("linux-x86_64") {
        operatingSystem = OperatingSystemFamily.LINUX
        architecture = MachineArchitecture.X86_64
    }
    target("linux-aarch64") {
        operatingSystem = OperatingSystemFamily.LINUX
        architecture = MachineArchitecture.ARM64
    }
    target("darwin-aarch64") {
        operatingSystem = OperatingSystemFamily.MACOS
        architecture = MachineArchitecture.ARM64
    }
    target("darwin-x86_64") {
        operatingSystem = OperatingSystemFamily.MACOS
        architecture = MachineArchitecture.X86_64
    }
    target("windows-x86_64") {
        operatingSystem = OperatingSystemFamily.WINDOWS
        architecture = MachineArchitecture.X86_64
    }

    // Bouncy Castle JARs fail as: jlink failed with: Error: signed modular JAR is currently not
    // supported:
    jlinkOptions.addAll("--ignore-signing-information")
}

// package 'cremony' binary from ':hedera-cryptography-wraps' project into jars
val nativeBin = configurations.dependencyScope("nativeBin")
val nativeBinPath =
    configurations.resolvable("nativeBinPath") {
        extendsFrom(nativeBin.get())
        attributes.attribute(Usage.USAGE_ATTRIBUTE, objects.named("native-bin"))
    }

dependencies { nativeBin(project(":hedera-cryptography-wraps")) }

tasks.processResources { from(nativeBinPath) { include("com/hedera/nativelib/ceremony/**") } }
