module com.hedera.cryptography.tss.test.fixtures {
    requires transitive com.hedera.cryptography.bls;
    requires transitive com.hedera.cryptography.pairings.api;
    requires transitive com.hedera.cryptography.utils.test.fixtures;
    requires com.hedera.cryptography.utils;
    requires org.junit.jupiter.api;
    requires static transitive com.hedera.cryptography.tss;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.tss.test.fixtures;
    exports com.hedera.cryptography.tss.test.fixtures.beaver;
}
