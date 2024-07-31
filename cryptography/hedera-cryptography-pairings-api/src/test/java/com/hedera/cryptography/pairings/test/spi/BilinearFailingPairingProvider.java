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

package com.hedera.cryptography.pairings.test.spi;

import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.spi.BilinearPairingProvider;
import com.hedera.cryptography.pairings.test.api.TestCurves;

/**
 * A {@link BilinearPairingProvider} implementation that will always fail the initialization process.
 */
public class BilinearFailingPairingProvider extends BilinearPairingProvider {
    @Override
    protected void doInit() {
        throw new RuntimeException("this is a failing provider");
    }

    @Override
    public Curve curve() {
        return TestCurves.FAIL_CURVE;
    }

    @Override
    public BilinearPairing pairing() {
        return null;
    }
}
