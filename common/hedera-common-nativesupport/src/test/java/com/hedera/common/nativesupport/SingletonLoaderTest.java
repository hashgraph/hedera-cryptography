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

package com.hedera.common.nativesupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.common.nativesupport.jni.Greeter;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class SingletonLoaderTest {
    @Test
    void testInitializeRaceCondition() throws InterruptedException {
        final int numThreads = 10000;
        final AtomicInteger counter = new AtomicInteger(0);
        final AtomicInteger successful = new AtomicInteger(0);
        final SingletonLoader<Greeter> singletonLoader = new SingletonLoader<>("greeter", new Greeter());
        final Callable<Greeter> callable = () -> {
            counter.incrementAndGet();
            var value = singletonLoader.getInstance();
            successful.incrementAndGet();
            return value;
        };

        try (ExecutorService executor = Executors.newFixedThreadPool(numThreads)) {
            final List<Future<Greeter>> futures = executor.invokeAll(Collections.nCopies(numThreads, callable));
            executor.shutdown();
            assertTrue(executor.awaitTermination(1, TimeUnit.MINUTES));
            assertEquals(numThreads, counter.get());
            assertEquals(numThreads, successful.get());
            for (Future<Greeter> future : futures) {
                assertTrue(future.isDone());
                assertSame(singletonLoader.getInstance(), future.resultNow());
            }
        }
    }
}
