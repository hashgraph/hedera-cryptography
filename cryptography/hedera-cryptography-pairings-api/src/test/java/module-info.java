import com.hedera.cryptography.pairings.test.spi.TestPairingFriendlyCurve.FailingCurve;
import com.hedera.cryptography.pairings.test.spi.TestPairingFriendlyCurve.TestAltBn128;
import com.hedera.cryptography.pairings.test.spi.TestPairingFriendlyCurve.TestBn;

open module com.hedera.cryptography.pairings.test {
    requires com.hedera.cryptography.pairings.api;
    requires com.hedera.cryptography.pairings.test.fixtures;
    requires com.hedera.cryptography.utils.test.fixtures;

    uses com.hedera.cryptography.pairings.api.PairingFriendlyCurve;

    provides com.hedera.cryptography.pairings.api.PairingFriendlyCurve with
            TestAltBn128,
            TestBn,
            FailingCurve;
}
