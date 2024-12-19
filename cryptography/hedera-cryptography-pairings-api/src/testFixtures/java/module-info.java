import com.hedera.cryptography.pairings.test.fixtures.curve.TestFixtureCurves.FailingCurve;
import com.hedera.cryptography.pairings.test.fixtures.curve.TestFixtureCurves.FakeCurve;
import com.hedera.cryptography.pairings.test.fixtures.curve.TestFixtureCurves.TestBn;

module com.hedera.cryptography.pairings.test.fixtures {
    requires com.hedera.cryptography.utils;
    requires org.junit.jupiter.api;
    requires static transitive com.hedera.cryptography.pairings.api;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.pairings.test.fixtures.curve;
    exports com.hedera.cryptography.pairings.test.fixtures.extensions.serialization;

    provides com.hedera.cryptography.pairings.api.PairingFriendlyCurve with
            FakeCurve,
            TestBn,
            FailingCurve;
}
