/**
 * This module provides a cryptography utility to create EC PublicKeys and EC PrivateKeys.
 */
module com.hedera.cryptography.ecKeyGen {
    requires com.hedera.common.nativesupport;
    requires com.hedera.cryptography.pairings.api;
    requires com.hedera.cryptography.pairings.signatures;
    requires com.github.spotbugs.annotations;
    requires com.google.protobuf;
}
