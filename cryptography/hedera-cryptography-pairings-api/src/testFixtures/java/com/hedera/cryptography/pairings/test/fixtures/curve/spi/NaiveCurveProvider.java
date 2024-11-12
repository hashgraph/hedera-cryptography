/*
 * Copyright (C) 2024 Hedera Hashgraph, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hedera.cryptography.pairings.test.fixtures.curve.spi;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve;
import com.hedera.cryptography.pairings.test.fixtures.curve.TestFixtureCurves;
import java.util.concurrent.atomic.AtomicInteger;
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
     * Counts the number of times {@link NaiveCurveProvider#doInit()} method gets invoked
     */
    private final AtomicInteger initializedCount = new AtomicInteger(0);

    /**
     * @return the number of times the {@link NaiveCurveProvider#doInit()}  method got invoked
     */
    public int getInitializedCount() {
        return initializedCount.get();
    }

    /**
     * Initializes the library.
     * @implNote This method is only called once.
     */
    @Override
    protected void doInit() {
        initializedCount.incrementAndGet();
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
