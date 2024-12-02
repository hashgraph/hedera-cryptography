/**
 *
 * This module provides utility classes for the cryptography modules.
 */
module com.hedera.cryptography.utils {
    requires transitive static com.github.spotbugs.annotations;

    exports com.hedera.cryptography.utils;
    exports com.hedera.cryptography.utils.serialization;
}
