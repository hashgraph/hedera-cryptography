/**
 * This module provides a cryptography utility to create EC PublicKeys and EC PrivateKeys.
 */
module com.hedera.cryptography.blskeygen {
    requires com.hedera.cryptography.pairings.api;
    requires com.hedera.cryptography.pairings.signatures;
    requires com.google.protobuf;
    requires static transitive com.github.spotbugs.annotations;
}
