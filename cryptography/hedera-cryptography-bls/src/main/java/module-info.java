/**
 *
 * This module provides cryptography primitives to create EC PublicKeys, EC PrivateKeys, and Signatures.
 */
module com.hedera.cryptography.bls {
    requires transitive com.hedera.cryptography.pairings.api;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.bls;

    uses com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider;
}
