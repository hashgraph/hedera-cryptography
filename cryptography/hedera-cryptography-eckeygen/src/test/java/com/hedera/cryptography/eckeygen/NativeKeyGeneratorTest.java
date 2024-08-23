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

package com.hedera.cryptography.eckeygen;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.curves.KnownCurves;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class NativeKeyGeneratorTest {

    private static final byte[] SK = new byte[] {
        111, -52, 71, -6, 21, 82, 41, -115, 53, -47, 34, -123, 121, -20, 52, -27, 5, -3, 8, 40, -4, -35, 12, 31, 35, 35,
        -76, -28, 121, -71, -34, 28, -50, 126, 50, 85, -6, -74, -93, -83, -125, -26, 70, 70, 87, -123, -16, -104, -60,
        122, 111, 42, -40, -67, -101, -38, 83, 106, -56, -60, 103, -34, 107, 1
    };

    @Test
    @SuppressWarnings("ResultOfMethodCallIgnored")
    void testInitializeRaceCondition() throws InterruptedException {
        final int numThreads = 10000;
        final AtomicInteger counter = new AtomicInteger(0);
        final AtomicInteger successful = new AtomicInteger(0);
        final NativeKeyGenerator keyGenerator = new NativeKeyGenerator() {
            @NonNull
            @Override
            public NativeKeyGenerator initialize() {
                counter.incrementAndGet();
                try {
                    var value = super.initialize();
                    successful.incrementAndGet();
                    return value;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
        final List<Callable<Void>> callables = IntStream.range(0, numThreads)
                .boxed()
                .map(i -> (Callable<Void>) () -> {
                    keyGenerator.initialize();
                    return null;
                })
                .toList();

        try (ExecutorService executor = Executors.newFixedThreadPool(numThreads)) {
            executor.invokeAll(callables);
            executor.shutdown();
            executor.awaitTermination(1, TimeUnit.MINUTES);
            assertEquals(numThreads, counter.get());
            assertEquals(numThreads, successful.get());
        }
    }

    @Test
    void testInitialize() {

        NativeKeyGenerator nativeKeyGenerator = new NativeKeyGenerator();
        assertDoesNotThrow(nativeKeyGenerator::initialize);
    }

    @Test
    void testMultipleInitialize() {
        NativeKeyGenerator nativeKeyGenerator = new NativeKeyGenerator();
        nativeKeyGenerator.initialize();
        assertDoesNotThrow(nativeKeyGenerator::initialize);
    }

    @Test
    void testKeyPairGeneration() {
        NativeKeyGenerator nativeKeyGenerator = new NativeKeyGenerator();
        nativeKeyGenerator.initialize();
        byte[][] output = nativeKeyGenerator.generateKeyPair(KnownCurves.ALT_BN128.getId());
        assertEquals(2, output.length);
        assertNotNull(output[0]);
        assertNotNull(output[1]);
    }

    @Test
    void testKeyPublicKey() {
        NativeKeyGenerator nativeKeyGenerator = new NativeKeyGenerator();
        nativeKeyGenerator.initialize();
        byte[] output = nativeKeyGenerator.generatePublicKey(KnownCurves.ALT_BN128.getId(), SK);
        assertNotNull(output);
    }

    @Test
    void testTwoWays() {
        NativeKeyGenerator nativeKeyGenerator = new NativeKeyGenerator();
        nativeKeyGenerator.initialize();
        byte[][] output = nativeKeyGenerator.generateKeyPair(KnownCurves.ALT_BN128.getId());
        assertEquals(2, output.length);
        assertNotNull(output[0]);
        assertNotNull(output[1]);
        byte[] pk = nativeKeyGenerator.generatePublicKey(KnownCurves.ALT_BN128.getId(), output[0]);
        assertArrayEquals(output[1], pk);
    }
}
