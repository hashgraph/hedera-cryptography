open module com.hedera.cryptography.pairings.test {
    requires com.hedera.cryptography.altbn128;
    requires com.hedera.cryptography.pairings.api;
    requires com.hedera.cryptography.pairings.test.fixtures;
    requires com.hedera.cryptography.utils.test.fixtures;
    requires org.junit.jupiter.params;

    uses com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
}
