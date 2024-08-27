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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.hedera.common.nativesupport.jni.Greeter;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class NativeLibraryTest {

    private static Stream<Object[]> combinedParameters() {
        return Stream.of(OperatingSystem.values())
                .flatMap(os -> Stream.of(Architecture.values()).map(arch -> new Object[]{os, arch}));
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void testWithNameAndCustomExtensions(OperatingSystem operatingSystem, Architecture architecture) {
        final Map<OperatingSystem, String> extensions =
                Map.of(OperatingSystem.WINDOWS, "win", OperatingSystem.LINUX, "lx", OperatingSystem.DARWIN, "dar");
        NativeLibrary library = NativeLibrary.withName("libcustom", extensions);
        assertNotNull(library);

        try (MockedStatic<OperatingSystem> osStatic = Mockito.mockStatic(OperatingSystem.class);
                MockedStatic<Architecture> archStatic = Mockito.mockStatic(Architecture.class)) {
            osStatic.when(OperatingSystem::current).thenReturn(operatingSystem);
            archStatic.when(Architecture::current).thenReturn(architecture);

            assertEquals(
                    "software/%s/%s/libcustom.%s"
                            .formatted(
                                    operatingSystem.name().toLowerCase(),
                                    architecture.name().toLowerCase(),
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
    void testWithNameAndEmptyExtensions(OperatingSystem operatingSystem, Architecture architecture) {
        final Map<OperatingSystem, String> extensions = Map.of();
        NativeLibrary library = NativeLibrary.withName("libcustom", extensions);
        assertNotNull(library);

        try (MockedStatic<OperatingSystem> osStatic = Mockito.mockStatic(OperatingSystem.class);
                MockedStatic<Architecture> archStatic = Mockito.mockStatic(Architecture.class)) {
            osStatic.when(OperatingSystem::current).thenReturn(operatingSystem);
            archStatic.when(Architecture::current).thenReturn(architecture);

            assertEquals(
                    "software/%s/%s/libcustom"
                            .formatted(
                                    operatingSystem.name().toLowerCase(),
                                    architecture.name().toLowerCase()),
                    library.locationInJar());
        }
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void testWithNameAndBlankExtensions(OperatingSystem operatingSystem, Architecture architecture) {
        final Map<OperatingSystem, String> extensions =
                Map.of(OperatingSystem.WINDOWS, "", OperatingSystem.LINUX, "", OperatingSystem.DARWIN, "");
        NativeLibrary library = NativeLibrary.withName("libcustom", extensions);
        assertNotNull(library);

        try (MockedStatic<OperatingSystem> osStatic = Mockito.mockStatic(OperatingSystem.class);
                MockedStatic<Architecture> archStatic = Mockito.mockStatic(Architecture.class)) {
            osStatic.when(OperatingSystem::current).thenReturn(operatingSystem);
            archStatic.when(Architecture::current).thenReturn(architecture);

            assertEquals(
                    "software/%s/%s/libcustom"
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
        // Load native library greeter.dll (Windows) or greeter.so (Linux) greeter.dylib (Mac)
        NativeLibrary.withName("greeter").install(this.getClass());
        assertDoesNotThrow(() -> new Greeter().getGreeting());
    }

    @Test
    void testInstallInvokeAndResult() {
        // Load native library greeter.dll (Windows) or greeter.so (Linux) greeter.dylib (Mac)
        final NativeLibrary library = NativeLibrary.withName("greeter");
        assertNotNull(library.locationInJar(), "Should have found location in jar");
        assertDoesNotThrow(() -> library.install(this.getClass()));
        assertEquals("Hello, World from C++!", new Greeter().getGreeting());

    }
}
