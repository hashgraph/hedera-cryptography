plugins {
    id("org.gradlex.extra-java-module-info")
    id("org.gradlex.java-module-dependencies")
}

group = "com.hedera.platform"

extraJavaModuleInfo {
    failOnMissingModuleInfo.set(true)

    automaticModule("com.goterl:resource-loader", "resource.loader")
    automaticModule("com.goterl:lazysodium-java", "lazysodium.java")
}

