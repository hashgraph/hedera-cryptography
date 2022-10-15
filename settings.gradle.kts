plugins {
    id("com.gradle.enterprise").version("3.10.3")
}

rootProject.name = "hedera-bls-cryptography"

include(":hedera-bls-api")
include(":hedera-bls-rust-jni")

dependencyResolutionManagement {
    @Suppress("UnstableApiUsage")
    versionCatalogs {
        // The libs of this catalog are the **ONLY** ones that are authorized to be part of the runtime
        // distribution. These libs can be depended on during compilation, or bundled as part of runtime.
        create("libs") {
            // Define the approved version numbers
            // Third-party dependency versions

            // JNI
            version("resource-loader-version", "2.0.2")
            version("jna-version", "5.9.0")

            // Define the individual libraries
            library("resource-loader", "com.goterl", "resource-loader").versionRef("resource-loader-version")
            library("jna", "net.java.dev.jna", "jna").versionRef("jna-version")
        }
    }
}

gradleEnterprise {
    buildScan {
        termsOfServiceUrl = "https://gradle.com/terms-of-service"
        termsOfServiceAgree = "yes"
    }
}
