/**
 * Alt bn-128 implementation of the pairings api
 */
open module com.hedera.cryptography.testfixtures.altbn128 {
    requires com.hedera.cryptography.utils.test.fixtures;
    requires com.github.spotbugs.annotations;
    requires com.google.gson;

    exports com.hedera.cryptography.testfixtures.altbn128;
}
