module com.hedera.cryptography.utils.test.fixtures {
    requires transitive org.junit.jupiter.api;
    requires jakarta.inject;
    requires static transitive com.hedera.cryptography.utils;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.utils.test.fixtures.stream;
    exports com.hedera.cryptography.utils.test.fixtures.rng;
    exports com.hedera.cryptography.utils.test.fixtures;
}
