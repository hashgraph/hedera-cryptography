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
    /**
     * Test that the runIfNeeded method only runs the provided action once for each key.
     */
    @Test
    void concurrencyTest() {
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
                        () -> runOnlyOnce.runIfNeeded(key, counter::incrementAndGet)
                ));
            }
        }
        for (Future<?> future : futures) {
            assertDoesNotThrow(() -> future.get(5, TimeUnit.SECONDS),
                    "Futures are expected to complete quickly and without exception");
        }
        assertEquals(1, counter1.get(), "Counter1 should have been incremented only once");
        assertEquals(1, counter2.get(), "Counter2 should have been incremented only once");
    }

    /**
     * Tests exception handing in the runIfNeeded method.
     */
    @Test
    void exceptionTest() {
        final int key = 0;
        final RunOnlyOnce<Integer> runOnlyOnce = new RunOnlyOnce<>();
        assertThrows(
                RuntimeException.class,
                () -> runOnlyOnce.runIfNeeded(key, () -> {
                    throw new RuntimeException();
                }),
                "Exceptions should be propagated"
        );
        final AtomicBoolean ran = new AtomicBoolean(false);
        assertDoesNotThrow(() -> runOnlyOnce.runIfNeeded(key, () -> ran.set(true)),
                "This call should not throw an exception");
        assertTrue(ran.get(),
                "Although the same keys is used twice, the first invocation threw an exception, so the second should run");
    }
}