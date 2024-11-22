module com.hedera.cryptography.pairings.test.fixtures {
    requires com.hedera.cryptography.utils;
    requires static transitive com.hedera.cryptography.pairings.api;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.pairings.test.fixtures.curve;

    provides com.hedera.cryptography.pairings.api.PairingFriendlyCurve with
            com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve;
}
