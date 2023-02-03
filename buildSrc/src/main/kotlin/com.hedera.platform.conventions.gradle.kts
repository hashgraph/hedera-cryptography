import com.adarshr.gradle.testlogger.theme.ThemeType

plugins {
    java
    id("com.adarshr.test-logger")
    id("com.gorylenko.gradle-git-properties")
    id("com.hedera.platform.jpms-modules")
    id("com.hedera.platform.repositories")
    id("com.hedera.platform.spotless-conventions")
    id("com.hedera.platform.spotless-java-conventions")
    id("com.hedera.platform.spotless-kotlin-conventions")
}

group = "com.hedera.platform"


java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
        @Suppress("UnstableApiUsage")
        vendor.set(JvmVendorSpec.ADOPTIUM)
    }
    modularity.inferModulePath.set(true)
}

tasks.withType<AbstractArchiveTask> {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    fileMode = 664
    dirMode = 775
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

tasks.withType<Javadoc> {
    options.encoding = "UTF-8"
    (options as StandardJavadocDocletOptions)
        .tags("apiNote:a:API Note:", "implSpec:a:Implementation Requirements:", "implNote:a:Implementation Note:")
}

gitProperties {
    keys = listOf("git.build.version", "git.commit.id", "git.commit.id.abbrev")
}

testing {
    suites {
        @Suppress("UnstableApiUsage")
        val test by getting(JvmTestSuite::class) {
            useJUnitJupiter()
        }
    }
}

testlogger {
    theme = ThemeType.MOCHA
    slowThreshold = 10000
    showStandardStreams = true
    showPassedStandardStreams = false
    showSkippedStandardStreams = false
    showFailedStandardStreams = true
}
