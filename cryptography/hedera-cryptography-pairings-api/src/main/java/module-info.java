/**
 * This API will expose general arithmetic operations to work with Bilinear Pairings and EC curves that implementations must provide.
 */
module com.hedera.cryptography.pairings.api {
    uses com.hedera.cryptography.pairings.api.PairingFriendlyCurve;

    exports com.hedera.cryptography.pairings.api;
    exports com.hedera.cryptography.pairings.extensions;
    exports com.hedera.cryptography.pairings.api.curves;
    exports com.hedera.cryptography.pairings.extensions.serialization;

    requires transitive com.hedera.cryptography.utils;
    requires static transitive com.github.spotbugs.annotations;
}
