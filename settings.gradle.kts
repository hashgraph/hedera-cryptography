rootProject.name = "hedera-bls-cryptography"

pluginManagement {
    includeBuild("build-logic")
}

plugins {
    id("com.gradle.enterprise").version("3.10.3")
}

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

            // Define the individual libraries
            library("resource-loader", "com.goterl", "resource-loader").versionRef("resource-loader-version")
        }
    }
}

gradleEnterprise {
    buildScan {
        termsOfServiceUrl = "https://gradle.com/terms-of-service"
        termsOfServiceAgree = "yes"
    }
}