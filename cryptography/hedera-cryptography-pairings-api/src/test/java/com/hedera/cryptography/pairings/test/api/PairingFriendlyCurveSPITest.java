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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve;
import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

class PairingFriendlyCurveSPITest {

    @Test
    void testFindBilinearPairingFriendlyCurveProvider() {
        assertDoesNotThrow(() -> ServiceLoader.load(PairingFriendlyCurve.class));
        assertDoesNotThrow(() -> ServiceLoader.load(PairingFriendlyCurve.class).findFirst());
        assertTrue(
                () -> ServiceLoader.load(PairingFriendlyCurve.class).findFirst().isPresent());
        assertInstanceOf(
                NaiveCurve.class,
                ServiceLoader.load(PairingFriendlyCurve.class).findFirst().get());
    }

    @Test
    public void testConcurrency() throws Exception {
        int threadCount = 100;
        int taskCount = 100;
        try (ExecutorService executorService = Executors.newFixedThreadPool(threadCount)) {
            final List<Callable<ServiceLoader<PairingFriendlyCurve>>> callables =
                    Collections.nCopies(taskCount, () -> ServiceLoader.load(PairingFriendlyCurve.class));

            final var results = executorService.invokeAll(callables);
            for (Future<ServiceLoader<PairingFriendlyCurve>> result : results) {
                final ServiceLoader<PairingFriendlyCurve> actual = result.get();
                assertNotNull(actual);
                assertTrue(actual.findFirst().isPresent());
            }
            executorService.shutdown();
        }
    }
}
