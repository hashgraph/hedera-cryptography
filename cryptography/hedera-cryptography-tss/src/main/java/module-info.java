/**
 * This library implements the Threshold Signature Scheme (TSS) primitives.
 * TSS: A cryptographic signing scheme in which a minimum number of parties must collaborate
 *   to produce an aggregate signature that can be used to sign messages and an aggregate public key that can be used to verify that signature.
 */
module com.hedera.cryptography.tss {
    requires transitive com.hedera.cryptography.bls;
    requires transitive com.hedera.cryptography.pairings.api;
    requires transitive com.hedera.cryptography.utils;
    requires static transitive com.github.spotbugs.annotations;

    exports com.hedera.cryptography.tss.api;
    exports com.hedera.cryptography.tss.extensions.serialization;
}
