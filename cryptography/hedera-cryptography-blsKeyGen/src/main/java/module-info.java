/**
 * This module provides cryptography primitives to create EC PublicKeys, EC PrivateKeys, and Signatures.
 */
module com.hedera.cryptography.blsKeyGen {
    requires com.hedera.common.nativesupport;
    requires com.hedera.cryptography.pairings.api;
    requires com.hedera.cryptography.pairings.signatures;
    requires com.github.spotbugs.annotations;
    requires com.google.protobuf;

    opens software.darwin.arm64;
// opens software.linux.amd64;
// opens software.windows.amd64;
}
