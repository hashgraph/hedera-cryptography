/**
 * Alt bn-128 implementation of the pairings api
 */
module com.hedera.cryptography.altbn128 {
    requires com.hedera.common.nativesupport;
    requires com.hedera.cryptography.pairings.api;
    requires com.hedera.cryptography.utils;
    requires org.bouncycastle.provider;
    requires static transitive com.github.spotbugs.annotations;

    provides com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider with
            com.hedera.cryptography.altbn128.spi.AltBn128Provider;
}
