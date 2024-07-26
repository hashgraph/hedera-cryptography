/**
 * This module provides cryptography primitives to create EC PublicKeys, EC PrivateKeys, and Signatures.
 */
module com.hedera.cryptography.pairings.signatures {
    requires transitive com.hedera.cryptography.pairings.api;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.pairings.signatures.api;
}
