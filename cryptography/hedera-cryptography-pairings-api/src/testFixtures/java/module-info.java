module com.hedera.cryptography.pairings.test.fixtures {
    requires static transitive com.hedera.cryptography.pairings.api;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.pairings.test.fixtures.curve;
    exports com.hedera.cryptography.pairings.test.fixtures.curve.spi;

    provides com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider with
            com.hedera.cryptography.pairings.test.fixtures.curve.spi.NaiveCurveProvider;
}
