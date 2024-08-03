/**
 * This module provides cryptography primitives to create EC PublicKeys, EC PrivateKeys, and Signatures.
 */
module com.hedera.cryptography.blsKeyGen {
    requires transitive com.hedera.cryptography.pairings.signatures;
    requires com.hedera.common.nativesupport;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.blsKeyGen;
}
