
plugins {
    id("com.hedera.platform.conventions")
    id("com.hedera.platform.library")
}

dependencies {
    implementation(libs.resource.loader)
    implementation(libs.jna)
}
