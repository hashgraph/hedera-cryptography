import com.hedera.cryptography.pairings.spi.BilinearPairingProvider;

/**
 * This API will expose general arithmetic operations to work with Bilinear Pairings and EC curves that implementations must provide.
 */
module com.hedera.cryptography.pairings.api {
    uses BilinearPairingProvider;

    exports com.hedera.cryptography.pairings.api;

    requires static transitive com.github.spotbugs.annotations;
}
