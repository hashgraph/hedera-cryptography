import com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider;

/**
 * Alt bn-128 implementation of the pairings api
 */
module com.hedera.cryptography.altbn128 {
    requires com.hedera.common.nativesupport;
    requires com.hedera.cryptography.pairings.api;
    requires jdk.jshell;

    uses PairingFriendlyCurveProvider;

// TO add in the future:
// provides com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider with
//        AltBn128BilinearPairingProvider;
}
