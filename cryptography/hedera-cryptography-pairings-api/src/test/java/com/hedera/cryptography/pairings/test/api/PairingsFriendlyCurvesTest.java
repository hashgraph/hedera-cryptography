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

package com.hedera.cryptography.pairings.test.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider;
import com.hedera.cryptography.pairings.test.fixtures.curve.TestFixtureCurves;
import com.hedera.cryptography.pairings.test.fixtures.curve.spi.NaiveCurveProvider;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Test;

class PairingsFriendlyCurvesTest {

    @Test
    void implementedCurveIsFound() {
        assertDoesNotThrow(() -> PairingFriendlyCurves.instanceFor(TestFixtureCurves.NO_PAIRING_CURVE));
    }

    @Test
    void multipleCallsReturnSameInstance() {
        PairingFriendlyCurveProvider expected = PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE);
        assertDoesNotThrow(() -> PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE));
        assertSame(expected, PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE));
    }

    @Test
    void bilinearPairingIsInitialized() {
        PairingFriendlyCurveProvider expected = PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE);
        NaiveCurveProvider secondRequest =
                ((NaiveCurveProvider) PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE));
        assertEquals(1, secondRequest.getInitializedCount());
        assertSame(expected, secondRequest);
    }

    @Test
    void multipleInitializationsAreIgnored() {
        NaiveCurveProvider bilinearPairingProvider =
                (NaiveCurveProvider) PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE);
        bilinearPairingProvider.init();
        assertDoesNotThrow(
                bilinearPairingProvider
                        ::init); // BilinearPairingMockProvider is implemented so that if the underlying impl is called
        // multipleTimes throws exception
    }

    @Test
    void unknownCurveThrowsException() {
        assertThrows(
                NoSuchElementException.class, () -> PairingFriendlyCurves.instanceFor(TestCurves.NON_EXISTENT_CURVE));
    }

    @Test
    void failingCurveThrowsException() {
        assertThrows(IllegalStateException.class, () -> PairingFriendlyCurves.instanceFor(TestCurves.FAIL_CURVE));
    }
}
