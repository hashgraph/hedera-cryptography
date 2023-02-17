import com.hedera.platform.bls.impl.spi.Bls12381Provider;

module com.hedera.platform.bls.impl {
    exports com.hedera.platform.bls.impl.spi;
    exports com.hedera.platform.bls.impl to
            com.hedera.platform.bls.impl.test;

    requires resource.loader;
    requires com.sun.jna;
    requires org.apache.logging.log4j;
    requires org.apache.commons.lang3;
    requires org.apache.commons.io;
    requires com.hedera.platform.bls.api;

    provides com.hedera.platform.bls.spi.BilinearMapProvider with
            Bls12381Provider;
}
