import com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider;
import com.hedera.cryptography.pairings.test.fixtures.curve.spi.NaiveCurveProvider;

module com.hedera.cryptography.pairings.test.fixtures {
    requires com.hedera.cryptography.utils;
    requires static transitive com.hedera.cryptography.pairings.api;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.pairings.test.fixtures.curve;
    exports com.hedera.cryptography.pairings.test.fixtures.curve.spi;

    provides PairingFriendlyCurveProvider with
            NaiveCurveProvider;
}
