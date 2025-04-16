// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.common.nativesupport.jni.Greeter;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class NativeLibraryTest {

    private static Stream<Object[]> combinedParameters() {
        return Stream.of(OperatingSystem.values())
                .flatMap(os -> Stream.of(Architecture.values()).map(arch -> new Object[] {os, arch}));
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void testWithNameAndCustomExtensions(OperatingSystem operatingSystem, Architecture architecture) {
        final Map<OperatingSystem, String> extensions =
                Map.of(OperatingSystem.WINDOWS, "win", OperatingSystem.LINUX, "lx", OperatingSystem.DARWIN, "dar");
        final Map<OperatingSystem, String> prefixes =
                Map.of(OperatingSystem.WINDOWS, "pwin", OperatingSystem.LINUX, "plx", OperatingSystem.DARWIN, "pdar");
        NativeLibrary library = NativeLibrary.withName("custom", prefixes, extensions);
        assertNotNull(library);

        try (MockedStatic<OperatingSystem> osStatic = Mockito.mockStatic(OperatingSystem.class);
                MockedStatic<Architecture> archStatic = Mockito.mockStatic(Architecture.class)) {
            osStatic.when(OperatingSystem::current).thenReturn(operatingSystem);
            archStatic.when(Architecture::current).thenReturn(architecture);

            assertEquals(
                    "com/hedera/nativelib/custom/%s/%s/%scustom.%s"
                            .formatted(
                                    operatingSystem.name().toLowerCase(),
                                    architecture.name().toLowerCase(),
                                    prefixes.get(operatingSystem),
                                    extensions.get(operatingSystem)),
                    library.locationInJar());
        }
    }

    @Test
    void testWithNameUsingDefaultExtensions() {
        NativeLibrary library = NativeLibrary.withName("libdefault");
        assertNotNull(library);
        assertEquals("libdefault", library.name());
        assertNotEquals("", library.locationInJar());
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void testWithNameAndEmptyPrefixAndExtensions(OperatingSystem operatingSystem, Architecture architecture) {
        final NativeLibrary library = NativeLibrary.withName("custom", Map.of(), Map.of());
        assertNotNull(library);

        try (MockedStatic<OperatingSystem> osStatic = Mockito.mockStatic(OperatingSystem.class);
                MockedStatic<Architecture> archStatic = Mockito.mockStatic(Architecture.class)) {
            osStatic.when(OperatingSystem::current).thenReturn(operatingSystem);
            archStatic.when(Architecture::current).thenReturn(architecture);

            assertEquals(
                    "com/hedera/nativelib/custom/%s/%s/custom"
                            .formatted(
                                    operatingSystem.name().toLowerCase(),
                                    architecture.name().toLowerCase()),
                    library.locationInJar());
        }
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void testWithOnlyOneOsPrefix(OperatingSystem operatingSystem, Architecture architecture) {
        final Map<OperatingSystem, String> prefixes = Map.of(OperatingSystem.WINDOWS, "foo");
        final NativeLibrary library = NativeLibrary.withName("custom", prefixes, Map.of());
        assertNotNull(library);

        try (MockedStatic<OperatingSystem> osStatic = Mockito.mockStatic(OperatingSystem.class);
                MockedStatic<Architecture> archStatic = Mockito.mockStatic(Architecture.class)) {
            osStatic.when(OperatingSystem::current).thenReturn(operatingSystem);
            archStatic.when(Architecture::current).thenReturn(architecture);

            assertEquals(
                    "com/hedera/nativelib/custom/%s/%s/%scustom"
                            .formatted(
                                    operatingSystem.name().toLowerCase(),
                                    architecture.name().toLowerCase(),
                                    prefixes.getOrDefault(operatingSystem, "")),
                    library.locationInJar());
        }
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void testWithNameAndBlankExtensions(OperatingSystem operatingSystem, Architecture architecture) {
        final Map<OperatingSystem, String> emptyStrings =
                Map.of(OperatingSystem.WINDOWS, "", OperatingSystem.LINUX, "", OperatingSystem.DARWIN, "");
        NativeLibrary library = NativeLibrary.withName("custom", emptyStrings, emptyStrings);
        assertNotNull(library);

        try (MockedStatic<OperatingSystem> osStatic = Mockito.mockStatic(OperatingSystem.class);
                MockedStatic<Architecture> archStatic = Mockito.mockStatic(Architecture.class)) {
            osStatic.when(OperatingSystem::current).thenReturn(operatingSystem);
            archStatic.when(Architecture::current).thenReturn(architecture);

            assertEquals(
                    "com/hedera/nativelib/custom/%s/%s/custom"
                            .formatted(
                                    operatingSystem.name().toLowerCase(),
                                    architecture.name().toLowerCase()),
                    library.locationInJar());
        }
    }

    @Test
    public void testInstallExistentLib() {
        final NativeLibrary library = NativeLibrary.withName("greeter");
        assertNotNull(library.locationInJar(), "Should have found location in jar");
        assertDoesNotThrow(() -> library.install(this.getClass()));
    }

    @Test
    void testInstallAndInvoke() {
        // Load native library greeter.dll (Windows) or libgreeter.so (Linux) libgreeter.dylib (Mac)
        NativeLibrary.withName("greeter").install(this.getClass());
        assertDoesNotThrow(() -> new Greeter().getGreeting());
    }

    @Test
    void testInstallInvokeAndResult() {
        // Load native library greeter.dll (Windows) or libgreeter.so (Linux) libgreeter.dylib (Mac)
        final NativeLibrary library = NativeLibrary.withName("greeter");
        assertNotNull(library.locationInJar(), "Should have found location in jar");
        assertDoesNotThrow(() -> library.install(this.getClass()));
        assertEquals("Hello, World from C++!", new Greeter().getGreeting());
    }

    @Test
    void testConcurrentLoading() throws InterruptedException {
        int numThreads = 20;
        final Callable<Void> callable = () -> {
            NativeLibrary.withName("greeter").install(this.getClass());
            return null;
        };
        try (final ExecutorService executor = Executors.newFixedThreadPool(numThreads)) {
            final List<Future<Void>> futures = executor.invokeAll(Collections.nCopies(numThreads, callable));
            executor.shutdown();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
            for (final Future<Void> future : futures) {
                assertTrue(future.isDone(), "All tasks should be done");
                assertDoesNotThrow(() -> future.get(), "All tasks should have completed without an exception");
            }
        }
        assertDoesNotThrow(() -> new Greeter().getGreeting(), "Should be able to invoke the native method");
    }
}
