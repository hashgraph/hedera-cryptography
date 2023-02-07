import com.hedera.platform.bls.spi.BilinearMapProvider;

module com.hedera.platform.bls.api {
    exports com.hedera.platform.bls.api;
    exports com.hedera.platform.bls.spi;

    uses BilinearMapProvider;
}
