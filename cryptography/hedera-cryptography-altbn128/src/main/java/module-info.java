import com.hedera.cryptography.altbn128.spi.AltBn128BilinearPairingProvider;

/**
 * Alt bn-128 implementation of the pairings api
 */
module com.hedera.cryptography.altbn128 {
    requires com.hedera.common.nativesupport;
    requires com.hedera.cryptography.pairings.api;
    requires jdk.jshell;

    uses com.hedera.cryptography.pairings.spi.BilinearPairingProvider;

    provides com.hedera.cryptography.pairings.spi.BilinearPairingProvider with
            AltBn128BilinearPairingProvider;
}
