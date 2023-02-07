import com.hedera.platform.bls.impl.test.spi.BLS12381ExperimentalProvider;
import com.hedera.platform.bls.impl.test.spi.BLS12381MockProvider;
import com.hedera.platform.bls.impl.test.spi.BLS12381StubProvider;

open module com.hedera.platform.bls.impl.test {
    // BLS Modules
    requires com.hedera.platform.bls.api;
    requires com.hedera.platform.bls.impl;

    // JUnit
    requires org.junit.jupiter.api;
    requires org.junit.jupiter.params;

    // Mockito
    requires org.mockito;
    requires org.mockito.junit.jupiter;

    // AssertJ
    requires org.assertj.core;

    provides com.hedera.platform.bls.spi.BilinearMapProvider with
            BLS12381MockProvider,
            BLS12381ExperimentalProvider,
            BLS12381StubProvider;
}
