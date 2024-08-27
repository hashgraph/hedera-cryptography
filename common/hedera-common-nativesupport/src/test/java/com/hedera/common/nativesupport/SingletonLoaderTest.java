package com.hedera.common.nativesupport;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.common.nativesupport.jni.Greeter;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class SingletonLoaderTest {
    @Test
    void testInitializeRaceCondition() throws InterruptedException {
        final int numThreads = 10000;
        final AtomicInteger counter = new AtomicInteger(0);
        final AtomicInteger successful = new AtomicInteger(0);
        final SingletonLoader<Greeter> singletonLoader = new SingletonLoader<>(
                "greeter",
                Greeter.class,
                Greeter::new
        );
        final Callable<Greeter> callable = ()-> {
                counter.incrementAndGet();
                try {
                    var value = singletonLoader.getInstance();
                    successful.incrementAndGet();
                    return value;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
        };
        final List<Callable<Greeter>> callables =
                Stream.generate(()->callable)
                        .limit(numThreads)
                        .toList();

        try (ExecutorService executor = Executors.newFixedThreadPool(numThreads)) {
            final List<Future<Greeter>> futures = executor.invokeAll(callables);
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