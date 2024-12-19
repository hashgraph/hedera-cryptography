// SPDX-License-Identifier: Apache-2.0
plugins { id("org.hiero.gradle.module.library") }

description =
    "Provides a set of generic functions for loading native libraries in different system architectures" +
        "when packaged in a jar, using a predefined organization so they can be accessed with JNI."

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("org.junit.jupiter.params")
    requires("org.mockito")
}
