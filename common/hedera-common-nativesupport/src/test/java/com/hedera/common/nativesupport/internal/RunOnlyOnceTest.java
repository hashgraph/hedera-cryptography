package com.hedera.common.nativesupport.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class RunOnlyOnceTest {
    @Test
    void testRunIfNeeded() {
        final int numThreads = 10;
        final RunOnlyOnce<Integer> runOnlyOnce = new RunOnlyOnce<>();
        final List<Future<?>> futures = new ArrayList<>();
        final AtomicInteger counter1 = new AtomicInteger(0);
        final AtomicInteger counter2 = new AtomicInteger(0);
        try (final ExecutorService executor = Executors.newFixedThreadPool(numThreads)) {
            for (int i = 0; i < 30; i++) {
                final int key = i % 2;
                final AtomicInteger counter = key == 0
                        ? counter1
                        : counter2;
                futures.add(executor.submit(
                        ()-> runOnlyOnce.runIfNeeded(key, counter::incrementAndGet)
                ));
            }
        }
        for (Future<?> future : futures) {
            assertDoesNotThrow(()->future.get(5, TimeUnit.SECONDS));
        }
        assertEquals(1, counter1.get());
        assertEquals(1, counter2.get());
    }
}