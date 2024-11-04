module com.hedera.cryptography.utils.test.fixtures {
    requires static transitive com.hedera.cryptography.utils;
    requires static transitive com.github.spotbugs.annotations;
    requires transitive org.junit.jupiter.api;
    requires jakarta.inject;

    exports com.hedera.cryptography.utils.test.fixtures.stream;
}
