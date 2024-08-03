import com.hedera.cryptography.pairings.test.spi.BilinearFailingPairingProvider;
import com.hedera.cryptography.pairings.test.spi.BilinearPairingMockProvider;

open module com.hedera.cryptography.pairings.test {
    requires transitive com.hedera.cryptography.pairings.api;
    requires org.junit.jupiter.api;

    uses com.hedera.cryptography.pairings.spi.BilinearPairingProvider;

    provides com.hedera.cryptography.pairings.spi.BilinearPairingProvider with
            BilinearPairingMockProvider,
            BilinearFailingPairingProvider;
}
