module com.hedera.platform.bls.impl {
    exports com.hedera.platform.bls.impl.spi;
    exports com.hedera.platform.bls.impl;

    requires resource.loader;
    requires com.sun.jna;
    requires org.apache.logging.log4j;
    requires org.apache.commons.lang3;
    requires org.apache.commons.io;
    requires com.hedera.platform.bls.api;

    provides com.hedera.platform.bls.spi.BilinearMapProvider with
            com.hedera.platform.bls.impl.spi.BLS12381Provider;
}
