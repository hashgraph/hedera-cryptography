import com.hedera.platform.bls.BLS12381BilinearMap;

module com.hedera.platform.bls {
    // com.hedera.platform.bls12381
    requires resource.loader;
    requires com.sun.jna;
    requires org.apache.logging.log4j;
    requires org.apache.commons.lang3;
    requires org.apache.commons.io;

    exports com.hedera.platform.bls;

    uses com.hedera.platform.bls.BilinearMap;
    provides com.hedera.platform.bls.BilinearMap with BLS12381BilinearMap;
}
