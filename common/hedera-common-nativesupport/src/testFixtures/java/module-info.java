module com.hedera.common.testfixtures {
    requires transitive com.github.spotbugs.annotations;
    requires transitive org.junit.jupiter.api;
    requires jakarta.inject;

    exports com.hedera.common.testfixtures.rng;
}
