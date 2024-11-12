import com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider;
import com.hedera.cryptography.pairings.test.spi.FailingPairingFriendlyCurveProvider;

open module com.hedera.cryptography.pairings.test {
    requires com.hedera.cryptography.pairings.api;
    requires com.hedera.cryptography.pairings.test.fixtures;
    requires com.hedera.cryptography.utils.test.fixtures;

    uses PairingFriendlyCurveProvider;

    provides PairingFriendlyCurveProvider with
            FailingPairingFriendlyCurveProvider;
}
