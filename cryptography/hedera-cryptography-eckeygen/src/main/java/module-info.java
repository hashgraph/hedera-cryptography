/**
 * This module provides a cryptography utility to create EC PublicKeys and EC PrivateKeys.
 */
module com.hedera.cryptography.eckeygen {
    requires com.hedera.common.nativesupport;
    requires com.hedera.cryptography.pairings.api;
    requires com.hedera.cryptography.pairings.signatures;
    requires com.google.protobuf;
    requires static transitive com.github.spotbugs.annotations;
}
