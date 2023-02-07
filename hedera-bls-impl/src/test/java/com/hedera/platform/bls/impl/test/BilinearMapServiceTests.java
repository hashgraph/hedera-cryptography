/*
 * Copyright (C) 2022-2023 Hedera Hashgraph, LLC
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
package com.hedera.platform.bls.impl.test;

import static org.assertj.core.api.Assertions.*;

import com.hedera.platform.bls.api.BilinearMap;
import com.hedera.platform.bls.impl.BLS12381BilinearMap;
import com.hedera.platform.bls.impl.spi.BLS12381Provider;
import com.hedera.platform.bls.impl.test.spi.BLS12381ExperimentalProvider;
import com.hedera.platform.bls.impl.test.spi.BLS12381MockProvider;
import com.hedera.platform.bls.impl.test.spi.BLS12381StubProvider;
import com.hedera.platform.bls.spi.BilinearMapProvider;
import com.hedera.platform.bls.spi.BilinearMapService;
import com.hedera.platform.bls.spi.ProviderType;
import com.hedera.platform.bls.spi.WellKnownAlgorithms;
import java.util.NoSuchElementException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@DisplayName("BilinearMapService Unit Tests")
@TestMethodOrder(MethodOrderer.DisplayName.class)
@ExtendWith(MockitoExtension.class)
class BilinearMapServiceTests {

    public static final String[] BLANK_STRING_INPUTS = new String[] {"", " ", "   ", "\n", "\t"};
    private static final int MAX_INVOCATIONS = 100;
    private static final String NO_SUCH_ALGORITHM = "no-such-algorithm";

    @Test
    @DisplayName("defaultInstance(): Verify Basic Behaviors")
    void defaultInstanceBasic() {
        final BilinearMap bilinearMap = BilinearMapService.defaultInstance();
        assertThat(bilinearMap).isNotNull().isInstanceOf(BLS12381BilinearMap.class);
    }

    @Test
    @DisplayName("defaultInstance(): Verify Repeated Invocations")
    void defaultInstanceRepeatedInvocations() {
        for (int i = 0; i < MAX_INVOCATIONS; i++) {
            BilinearMap bilinearMap = BilinearMapService.defaultInstance();
            assertThat(bilinearMap).isNotNull().isInstanceOf(BLS12381BilinearMap.class);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("instanceOfArguments")
    @DisplayName("instanceOf(ProviderType): Verify Basic Behaviors")
    void instanceOfBasic(ProviderType providerType, Class<?> instanceCheck) {
        final BilinearMap bilinearMap = BilinearMapService.instanceOf(WellKnownAlgorithms.BLS12_381, providerType);
        assertThat(bilinearMap).isNotNull().isInstanceOf(instanceCheck);
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("instanceOfArguments")
    @DisplayName("instanceOf(ProviderType): Verify Repeated Invocations")
    void instanceOfRepeatedInvocations(ProviderType providerType, Class<?> instanceCheck) {
        for (int i = 0; i < MAX_INVOCATIONS; i++) {
            BilinearMap bilinearMap = BilinearMapService.instanceOf(WellKnownAlgorithms.BLS12_381, providerType);
            assertThat(bilinearMap).isNotNull().isInstanceOf(instanceCheck);
        }
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("providerOfArguments")
    @DisplayName("providerOf(ProviderType): Verify Basic Behaviors")
    void providerOfBasic(ProviderType providerType, Class<?> providerCheck) {
        final BilinearMapProvider provider = BilinearMapService.providerOf(WellKnownAlgorithms.BLS12_381, providerType);
        assertThat(provider)
                .isNotNull()
                .isInstanceOf(providerCheck)
                .extracting(BilinearMapProvider::providerType)
                .isEqualTo(providerType);
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("providerOfArguments")
    @DisplayName("providerOf(ProviderType): Verify Repeated Invocations")
    void providerOfRepeatedInvocations(ProviderType providerType, Class<?> providerCheck) {
        for (int i = 0; i < MAX_INVOCATIONS; i++) {
            BilinearMapProvider provider = BilinearMapService.providerOf(WellKnownAlgorithms.BLS12_381, providerType);
            assertThat(provider)
                    .isNotNull()
                    .isInstanceOf(providerCheck)
                    .extracting(BilinearMapProvider::providerType)
                    .isEqualTo(providerType);
        }
    }

    @Test
    @DisplayName("runtimeInstanceOf(): Verify Basic Behaviors")
    void runtimeInstanceOfBasic() {
        final BilinearMap bilinearMap = BilinearMapService.runtimeInstanceOf(WellKnownAlgorithms.BLS12_381);
        assertThat(bilinearMap).isNotNull().isInstanceOf(BLS12381BilinearMap.class);
    }

    @Test
    @DisplayName("runtimeInstanceOf(): Verify Repeated Invocations")
    void runtimeInstanceOfRepeatedInvocations() {
        for (int i = 0; i < MAX_INVOCATIONS; i++) {
            BilinearMap bilinearMap = BilinearMapService.runtimeInstanceOf(WellKnownAlgorithms.BLS12_381);
            assertThat(bilinearMap).isNotNull().isInstanceOf(BLS12381BilinearMap.class);
        }
    }

    @Test
    @DisplayName("defaultInstance(): Never Throws Exception")
    void defaultInstanceDoesNotThrow() {
        assertThatCode(BilinearMapService::defaultInstance).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("instanceOf(): Throws NullPointer Exceptions")
    void instanceOfThrowsNullPointer() {
        final Throwable thrown = catchThrowable(() -> BilinearMapService.instanceOf(null));
        assertThat(thrown).isNotNull().isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("instanceOf(): Throws IllegalArgument Exceptions")
    void instanceOfThrowsIllegalArgument() {
        for (final String val : BLANK_STRING_INPUTS) {
            final Throwable thrown = catchThrowable(() -> BilinearMapService.instanceOf(val));
            assertThat(thrown).isNotNull().isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    @DisplayName("instanceOf(): Throws NoSuchElement Exceptions")
    void instanceOfThrowsNoSuchElement() {
        Throwable thrown = catchThrowable(() -> BilinearMapService.instanceOf(NO_SUCH_ALGORITHM));
        assertThat(thrown).isNotNull().isInstanceOf(NoSuchElementException.class);

        for (ProviderType providerType : ProviderType.values()) {
            thrown = catchThrowable(() -> BilinearMapService.instanceOf(NO_SUCH_ALGORITHM, providerType));
            assertThat(thrown).isNotNull().isInstanceOf(NoSuchElementException.class);
        }
    }

    @Test
    @DisplayName("runtimeInstanceOf(): Throws NullPointer Exceptions")
    void runtimeInstanceOfThrowsNullPointer() {
        final Throwable thrown = catchThrowable(() -> BilinearMapService.runtimeInstanceOf(null));
        assertThat(thrown).isNotNull().isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("runtimeInstanceOf(): Throws IllegalArgument Exceptions")
    void runtimeInstanceOfThrowsIllegalArgument() {
        for (final String val : BLANK_STRING_INPUTS) {
            final Throwable thrown = catchThrowable(() -> BilinearMapService.runtimeInstanceOf(val));
            assertThat(thrown).isNotNull().isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    @DisplayName("runtimeInstanceOf(): Throws NoSuchElement Exceptions")
    void runtimeInstanceOfThrowsNoSuchElement() {
        final Throwable thrown = catchThrowable(() -> BilinearMapService.runtimeInstanceOf(NO_SUCH_ALGORITHM));
        assertThat(thrown).isNotNull().isInstanceOf(NoSuchElementException.class);
    }

    @Test
    @DisplayName("providerOf(): Throws NullPointer Exceptions")
    void providerOfThrowsNullPointer() {
        final Throwable thrown = catchThrowable(() -> {
            BilinearMapService.providerOf(null);
        });
        assertThat(thrown).isNotNull().isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("providerOf(): Throws IllegalArgument Exceptions")
    void providerOfThrowsIllegalArgument() {
        for (final String val : BLANK_STRING_INPUTS) {
            final Throwable thrown = catchThrowable(() -> BilinearMapService.providerOf(val));
            assertThat(thrown).isNotNull().isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    @DisplayName("providerOf(): Throws NoSuchElement Exceptions")
    void providerOfThrowsNoSuchElement() {
        Throwable thrown = catchThrowable(() -> BilinearMapService.providerOf(NO_SUCH_ALGORITHM));
        assertThat(thrown).isNotNull().isInstanceOf(NoSuchElementException.class);

        for (ProviderType providerType : ProviderType.values()) {
            thrown = catchThrowable(() -> BilinearMapService.providerOf(NO_SUCH_ALGORITHM, providerType));
            assertThat(thrown).isNotNull().isInstanceOf(NoSuchElementException.class);
        }
    }

    @Test
    @DisplayName("runtimeProviderOf(): Verify Basic Behaviors")
    void runtimeProviderOfBasic() {
        final BilinearMapProvider provider = BilinearMapService.runtimeProviderOf(WellKnownAlgorithms.BLS12_381);
        assertThat(provider).isNotNull().isInstanceOf(BLS12381Provider.class);
    }

    @Test
    @DisplayName("runtimeProviderOf(): Verify Repeated Invocations")
    void runtimeProviderOfRepeatedInvocations() {
        for (int i = 0; i < MAX_INVOCATIONS; i++) {
            BilinearMapProvider provider = BilinearMapService.runtimeProviderOf(WellKnownAlgorithms.BLS12_381);
            assertThat(provider).isNotNull().isInstanceOf(BLS12381Provider.class);
        }
    }

    @Test
    @DisplayName("runtimeProviderOf(): Throws NullPointer Exceptions")
    void runtimeProviderOfThrowsNullPointer() {
        final Throwable thrown = catchThrowable(() -> {
            BilinearMapService.runtimeProviderOf(null);
        });
        assertThat(thrown).isNotNull().isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("runtimeProviderOf(): Throws IllegalArgument Exceptions")
    void runtimeProviderOfThrowsIllegalArgument() {
        for (final String val : BLANK_STRING_INPUTS) {
            final Throwable thrown = catchThrowable(() -> BilinearMapService.runtimeProviderOf(val));
            assertThat(thrown).isNotNull().isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    @DisplayName("runtimeProviderOf(): Throws NoSuchElement Exceptions")
    void runtimeProviderOfThrowsNoSuchElement() {
        final Throwable thrown = catchThrowable(() -> BilinearMapService.runtimeProviderOf(NO_SUCH_ALGORITHM));
        assertThat(thrown).isNotNull().isInstanceOf(NoSuchElementException.class);
    }

    @Test
    @DisplayName("refresh(): Never Throws Exception")
    void refreshDoesNotThrow() {
        assertThatCode(BilinearMapService::refresh).doesNotThrowAnyException();
    }

    static Stream<Arguments> instanceOfArguments() {
        return Stream.of(
                Arguments.of(ProviderType.RUNTIME, BLS12381BilinearMap.class),
                Arguments.of(ProviderType.MOCK, BLS12381MockProvider.Mock.class),
                Arguments.of(ProviderType.STUB, BLS12381StubProvider.Stub.class),
                Arguments.of(ProviderType.EXPERIMENTAL, BLS12381ExperimentalProvider.Experimental.class));
    }

    static Stream<Arguments> providerOfArguments() {
        return Stream.of(
                Arguments.of(ProviderType.RUNTIME, BLS12381Provider.class),
                Arguments.of(ProviderType.MOCK, BLS12381MockProvider.class),
                Arguments.of(ProviderType.STUB, BLS12381StubProvider.class),
                Arguments.of(ProviderType.EXPERIMENTAL, BLS12381ExperimentalProvider.class));
    }

    /*
    Example usage with a builder model:

    final Platform platform = new PlatformBuilder()
            .withConsensus(new SomeConsensusImpl())
            .withBilinearMap(BilinearMapService.runtimeProviderOf(WellKnownAlgorithms.BLS12_381))
            .........
            .build();
     */
}
