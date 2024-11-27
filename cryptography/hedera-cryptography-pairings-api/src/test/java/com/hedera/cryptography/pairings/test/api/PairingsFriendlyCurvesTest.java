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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve.FailingCurveException;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve.TestBn;
import com.hedera.cryptography.pairings.test.fixtures.curve.TestFixtureCurves;
import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class PairingsFriendlyCurvesTest {

    @Test
    void implementedCurveIsFound() {
        assertDoesNotThrow(() -> PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE));
    }

    @Test
    void multipleCallsReturnSameInstance() {
        PairingFriendlyCurve expected = PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE);
        assertDoesNotThrow(() -> PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE));
        assertSame(expected, PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE));
    }

    @Test
    void bilinearPairingIsInitialized() {
        IntStream.range(0, 10).forEach(i -> PairingFriendlyCurves.findInstance(TestFixtureCurves.TEST));
        assertEquals(1, ((TestBn) PairingFriendlyCurves.findInstance(TestFixtureCurves.TEST)).getInitializedCount());
    }

    @Test
    void unknownCurveThrowsException() {
        assertThrows(
                NoSuchElementException.class,
                () -> PairingFriendlyCurves.findInstance(TestFixtureCurves.NON_EXISTENT_CURVE));
    }

    @Test
    void failingCurveThrowsException() {
        assertThrows(
                FailingCurveException.class, () -> PairingFriendlyCurves.findInstance(TestFixtureCurves.FAIL_CURVE));
    }

    @Test
    public void testConcurrency() throws Exception {
        final int threadCount = 100;
        final int taskCount = 100;
        try (ExecutorService executorService = Executors.newFixedThreadPool(threadCount)) {
            final List<Callable<PairingFriendlyCurve>> callables = Collections.nCopies(
                    taskCount, () -> PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE));

            final var results = executorService.invokeAll(callables);
            for (final Future<PairingFriendlyCurve> result : results) {
                final PairingFriendlyCurve actual = result.get();
                assertNotNull(actual);
                assertEquals(TestFixtureCurves.NO_PAIRING_CURVE, actual.curve());
            }
            executorService.shutdown();
        }
    }
}
