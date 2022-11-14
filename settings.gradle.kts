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

            version("slf4j-version", "2.0.0")
            version("log4j-version", "2.17.2")

            // Define the individual libraries
            library("resource-loader", "com.goterl", "resource-loader").versionRef("resource-loader-version")
            library("jna", "net.java.dev.jna", "jna").versionRef("jna-version")
            // Log4j Bundle
            library("log4j-api", "org.apache.logging.log4j", "log4j-api").versionRef("log4j-version")
            library("log4j-core", "org.apache.logging.log4j", "log4j-core").versionRef("log4j-version")
            // Slf4j Bundle
            library("slf4j-api", "org.slf4j", "slf4j-api").versionRef("slf4j-version")
            library("slf4j-nop", "org.slf4j", "slf4j-nop").versionRef("slf4j-version")

            bundle("logging-api", listOf("log4j-api", "slf4j-api"))
            bundle("logging-impl", listOf("log4j-core", "slf4j-nop"))
        }
    }
}

gradleEnterprise {
    buildScan {
        termsOfServiceUrl = "https://gradle.com/terms-of-service"
        termsOfServiceAgree = "yes"
    }
}
