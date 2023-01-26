import com.hedera.platform.bls.impl.BLS12381BilinearMap;
import com.hedera.platform.bls.api.BilinearMap;

module com.hedera.platform.bls.impl {
    requires resource.loader;
    requires com.sun.jna;
    requires org.apache.logging.log4j;
    requires org.apache.commons.lang3;
    requires org.apache.commons.io;

    requires com.hedera.platform.bls.api;

    provides BilinearMap with BLS12381BilinearMap;
}
