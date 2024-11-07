package com.hedera.cryptography.pairings.test.fixtures.curve.spi;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve;
import com.hedera.cryptography.pairings.test.fixtures.curve.TestFixtureCurves;
import java.util.concurrent.atomic.AtomicReference;

/**
 * An SPI provider for {@link NaiveCurve}
 */
public class NaiveCurveProvider extends PairingFriendlyCurveProvider {

    /**
     * The instance being provided.
     */
    final AtomicReference<PairingFriendlyCurve> pairingFriendlyCurve = new AtomicReference<>();

    /**
     * Initializes the library.
     * @implNote This method is only called once.
     */
    @Override
    protected void doInit() {
        pairingFriendlyCurve.set(new NaiveCurve());
    }

    /**
     * Returns the implemented curve
     * @return the implemented curve.
     */
    @Override
    public Curve curve() {
        return TestFixtureCurves.NO_PAIRING_CURVE;
    }

    /**
     * The instance of {@link NaiveCurve}
     * @return the instance of {@link NaiveCurve}
     */
    @Override
    public PairingFriendlyCurve pairingFriendlyCurve() {
        return pairingFriendlyCurve.get();
    }
}