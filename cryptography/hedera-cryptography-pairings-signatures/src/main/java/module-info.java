module com.hedera.cryptography.pairings.signatures {
    requires transitive com.hedera.cryptography.pairings.api;
    requires static transitive com.github.spotbugs.annotations;
    exports com.hedera.cryptography.pairings.signatures.api;
}
