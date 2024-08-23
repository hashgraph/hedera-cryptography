/**
 * This API will expose general arithmetic operations to work with Bilinear Pairings and EC curves that implementations must provide.
 */
module com.hedera.cryptography.pairings.api {
    exports com.hedera.cryptography.pairings.api;
    exports com.hedera.cryptography.pairings.api.curves;
    exports com.hedera.cryptography.pairings.spi;

    uses com.hedera.cryptography.pairings.spi.BilinearPairingProvider;

    requires static transitive com.github.spotbugs.annotations;
}
