import com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider;
import com.hedera.cryptography.pairings.test.spi.FailingPairingFriendlyCurveProvider;
import com.hedera.cryptography.pairings.test.spi.PairingMockFriendlyCurveProvider;

open module com.hedera.cryptography.pairings.test {
    requires transitive com.hedera.cryptography.pairings.api;
    requires org.junit.jupiter.api;

    uses PairingFriendlyCurveProvider;

    provides PairingFriendlyCurveProvider with
            PairingMockFriendlyCurveProvider,
            FailingPairingFriendlyCurveProvider;
}
