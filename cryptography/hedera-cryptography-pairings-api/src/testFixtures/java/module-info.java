import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve.FailingCurve;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve.TestBn;

module com.hedera.cryptography.pairings.test.fixtures {
    requires com.hedera.cryptography.utils;
    requires static transitive com.hedera.cryptography.pairings.api;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.pairings.test.fixtures.curve;

    provides PairingFriendlyCurve with
            NaiveCurve,
            TestBn,
            FailingCurve;
}
