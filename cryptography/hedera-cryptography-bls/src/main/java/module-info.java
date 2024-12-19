/**
 *
 * This module provides cryptography primitives to create EC PublicKeys, EC PrivateKeys, and Signatures.
 */
module com.hedera.cryptography.bls {
    requires transitive com.hedera.cryptography.pairings.api;
    requires transitive com.hedera.cryptography.utils;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.bls;
    exports com.hedera.cryptography.bls.extensions.serialization;
    exports com.hedera.cryptography.asciiarmored;

    uses com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
}
