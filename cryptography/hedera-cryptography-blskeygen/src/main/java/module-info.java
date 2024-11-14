/**
 * This module provides a cryptography utility to create EC PublicKeys and EC PrivateKeys.
 */
module com.hedera.cryptography.blskeygen {
    requires transitive com.hedera.cryptography.bls;
    requires com.hedera.cryptography.pairings.api;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.blskeygen;
}
