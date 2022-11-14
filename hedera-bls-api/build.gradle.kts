
plugins {
    id("com.hedera.platform.conventions")
    id("com.hedera.platform.library")
}

dependencies {
    implementation(libs.resource.loader)
    implementation(libs.jna)
    implementation("net.java.dev.jna:jna:5.12.1")
    implementation(libs.bundles.logging.impl)
}
