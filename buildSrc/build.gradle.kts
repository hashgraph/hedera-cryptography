plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
    mavenCentral()
}

dependencies {
    implementation("org.gradlex:extra-java-module-info:1.0")
    implementation("net.swiftzer.semver:semver:1.1.2")
    implementation("com.diffplug.spotless:spotless-plugin-gradle:6.11.0")
    implementation("com.gorylenko.gradle-git-properties:gradle-git-properties:2.4.1")
    implementation("gradle.plugin.lazy.zoo.gradle:git-data-plugin:1.2.2")
    implementation("com.adarshr:gradle-test-logger-plugin:3.2.0")

    implementation("com.moandjiezana.toml:toml4j:0.7.2")
}
