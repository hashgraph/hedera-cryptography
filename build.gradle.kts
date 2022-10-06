plugins {
    id("java")
    `maven-publish`
    id("bls.conventions")
}

group = "com.hedera.platform"
version = "1.0"

repositories {
    mavenCentral()
    mavenLocal()
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.0")

    implementation("net.java.dev.jna:jna:5.12.1")
    implementation("com.goterl:resource-loader:2.0.2")
}

java.sourceSets["main"].java {
    srcDir("src/main/java/resources")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("bls") {
            groupId = "com.hedera.platform"
            artifactId = "hedera-bls-cryptography"
            version = "1.1"

            from(components["java"])
        }
    }
}
