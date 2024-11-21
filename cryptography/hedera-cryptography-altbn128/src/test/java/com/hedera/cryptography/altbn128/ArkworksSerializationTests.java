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

package com.hedera.cryptography.altbn128;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.altbn128.adapter.jni.ArkBn254Adapter;
import com.hedera.cryptography.altbn128.facade.ElementFacade;
import com.hedera.cryptography.altbn128.facade.FieldFacade;
import com.hedera.cryptography.altbn128.facade.GroupFacade;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * This class contains tests for the Arkworks serialization of the different types of elements in the AltBN128 curve.
 */
@WithRng
public class ArkworksSerializationTests {

    /**
     * Each element has unused bits, the expectation is that when generating a random element, these bits are unset.
     */
    @ParameterizedTest
    @EnumSource(ElementInfo.class)
    void unusedBitsAreUnset(final ElementInfo info, final Random rng) {
        final byte[] bytes = randomElementBytes(info, rng);
        final BitSet bitSet = BitSet.valueOf(bytes);

        for (final Integer unusedBit : info.getUnusedBits()) {
            assertFalse(bitSet.get(unusedBit), "Bit at index %d is set".formatted(unusedBit));
        }
    }

    /**
     * When deserializing and serializing an element, the bytes should remain the same.
     */
    @Test
    @Disabled("Arkworks mods the field element when a larger one is deserialized, so this test fails")
    void deserializeSerializeEquality() {
        final FieldFacade facade = new FieldFacade(ArkBn254Adapter.getInstance());
        final byte[] bytes = new byte[facade.size()];
        Arrays.fill(bytes, (byte) 0b11111111);

        assertArrayEquals(bytes, facade.fromBytes(bytes));
    }

    /**
     * Each element type has a zero element, the expectation is that when generating a zero element, all bits are unset
     * except for the zero flag bit, if it exists.
     */
    @ParameterizedTest
    @EnumSource(ElementInfo.class)
    void zeroElementBits(final ElementInfo info) {
        final byte[] bytes = getFacade(info).zero();
        final BitSet bitSet = BitSet.valueOf(bytes);

        // if the element has flags, all bits should be zero except the zero flag bit
        for (int i = 0; i < bytes.length; i++) {
            if (info.hasFlags() && info.getZeroFlagBitIndex() == i) {
                assertTrue(bitSet.get(i), "Zero flag bit is not set");
            } else {
                assertFalse(bitSet.get(i), "Bit at index %d is set".formatted(i));
            }
        }
    }

    /**
     * Flipping the Y coordinate flag in the uncompressed format is ignored by Arkworks.
     */
    @ParameterizedTest
    @EnumSource(
            value = ElementInfo.class,
            // Y coordinate flag is only present in group elements
            names = {"GROUP1_ELEMENT", "GROUP2_ELEMENT"})
    void equalsConsistencyYCoordinate(final ElementInfo info, final Random rng) {
        final byte[] bytes = randomElementBytes(info, rng);
        final BitSet bitSet = BitSet.valueOf(bytes);
        bitSet.flip(info.getYCoordinateFlagBitIndex());
        final byte[] flippedFlagBytes = bitSet.toByteArray();

        final ElementFacade facade = getFacade(info);
        assertTrue(facade.equals(bytes, flippedFlagBytes));
    }

    /**
     * If the zero element flag is set, all other bits are meaningless. Arkworks seems to ignore them, exept for the Y
     * coordinate flag bit.
     */
    @ParameterizedTest
    @EnumSource(
            value = ElementInfo.class,
            // Y coordinate flag is only present in group elements
            names = {"GROUP1_ELEMENT", "GROUP2_ELEMENT"})
    void equalsConsistencyZeroFlag(final ElementInfo info, final Random rng) {
        final ElementFacade facade = getFacade(info);
        final byte[] zeroBytes = facade.zero();
        final BitSet bitSet = BitSet.valueOf(zeroBytes);
        final Set<Integer> allOtherBits =
                IntStream.range(0, info.numberOfBits()).boxed().collect(Collectors.toSet());
        allOtherBits.remove(info.getZeroFlagBitIndex());
        allOtherBits.remove(info.getYCoordinateFlagBitIndex());

        // flip a random bit that is not a flag bit
        final List<Integer> bitsList = new ArrayList<>(allOtherBits.stream().toList());
        Collections.shuffle(bitsList, rng);
        bitSet.flip(bitsList.getFirst());

        assertTrue(
                facade.equals(zeroBytes, bitSet.toByteArray()),
                "When the zero bit flag is set, Arkwors seems to ignore all other bits, except for the Y flag bit");
        assertDoesNotThrow(() -> facade.fromBytes(bitSet.toByteArray()));

        // flip the Y coordinate flag bit
        bitSet.flip(info.getYCoordinateFlagBitIndex());

        assertThrows(
                AltBn128Exception.class,
                () -> facade.equals(zeroBytes, bitSet.toByteArray()),
                "Arkworks seems to fail the equality when the Y coordinate flag bit is flipped");
        assertThrows(IllegalArgumentException.class, () -> facade.fromBytes(bitSet.toByteArray()));
    }

    /**
     * Flipping any unused bit should throw an exception when deserializing the element.
     */
    @ParameterizedTest
    @EnumSource(
            value = ElementInfo.class,
            // Arkworks mods the field element when a larger one is deserialized
            // Until we figure out the resolution on this, we will disable the test for field elements
            names = {"GROUP1_ELEMENT", "GROUP2_ELEMENT"})
    void flippingUnusedBits(final ElementInfo info, final Random rng) {
        final byte[] bytes = randomElementBytes(info, rng);
        final BitSet bitSet = BitSet.valueOf(bytes);

        final List<Integer> unusedBits =
                new ArrayList<>(info.getUnusedBits().stream().toList());
        Collections.shuffle(unusedBits, rng);
        bitSet.flip(unusedBits.getFirst());

        final byte[] flippedBytes = bitSet.toByteArray();

        assertThrows(IllegalArgumentException.class, () -> getFacade(info).fromBytes(flippedBytes));
    }

    /**
     * Generate a random element and serialize it to bytes
     *
     * @param info The type of element to generate
     * @param rng  The random number generator
     * @return The bytes of the generated element
     */
    private static @NonNull byte[] randomElementBytes(final ElementInfo info, final Random rng) {
        final ElementFacade facade = getFacade(info);
        final byte[] seed = new byte[facade.randomSeedSize()];
        rng.nextBytes(seed);
        return facade.fromRandomSeed(seed);
    }

    /**
     * Get the facade for the given element info
     *
     * @param info The element info
     * @return The facade
     */
    private static @NonNull ElementFacade getFacade(final ElementInfo info) {
        return info == ElementInfo.FIELD_ELEMENT
                ? new FieldFacade(ArkBn254Adapter.getInstance())
                : new GroupFacade(
                        info.getGroup().getId(),
                        ArkBn254Adapter.getInstance(),
                        ArkBn254Adapter.getInstance().fieldElementsSize());
    }
}
