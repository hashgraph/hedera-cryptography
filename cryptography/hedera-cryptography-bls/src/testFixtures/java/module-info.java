module com.hedera.cryptography.bls.test.fixtures {
    requires com.hedera.cryptography.utils.test.fixtures;
    requires static transitive com.hedera.cryptography.bls;

    uses com.hedera.cryptography.pairings.api.PairingFriendlyCurve;

    exports com.hedera.cryptography.bls.test.fixtures;
}
