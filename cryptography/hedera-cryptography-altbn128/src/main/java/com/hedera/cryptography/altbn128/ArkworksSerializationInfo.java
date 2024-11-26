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

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * This enum contains Arkworks serialization information about the different types of elements that can be used in the
 * AltBN128 curve. Each element has a number of 254-bit numbers, and optionally flags in the last number.
 */
public enum ArkworksSerializationInfo {
    /** {@link AltBn128FieldElement} */
    FIELD_ELEMENT(1, false, null),
    /** {@link AltBn128GroupElement} with group {@link AltBN128CurveGroup#GROUP1} */
    GROUP1_ELEMENT(2, true, AltBN128CurveGroup.GROUP1),
    /** {@link AltBn128GroupElement} with group {@link AltBN128CurveGroup#GROUP2} */
    GROUP2_ELEMENT(4, true, AltBN128CurveGroup.GROUP2);

    /**
     * The size of each number in bytes. Note: the numbers are actually 254-bit, so the last 2 bits are either unused or
     * used for flags.
     */
    private static final int NUMBER_SIZE_BYTES = 32;
    /** The index of the Y coordinate flag starting from the last bit */
    private static final int BIT_FLAG_Y_COORDINATE_POSITION = 0;
    /** The index of the zero element flag starting from the last bit */
    private static final int BIT_FLAG_ZERO_POSITION = 1;
    private static final byte MASK_Y_COORDINATE = (byte) 0b10000000;
    private static final byte MASK_ZERO = 0b01000000;

    /** The number of 254-bit numbers contained in this element */
    private final int numberCount;
    /** Whether this element contains flags in the last number */
    private final boolean hasFlags;
    /** The group of the element, if it is a group element */
    private final AltBN128CurveGroup group;
    /** The set of bits that are unused in the serialization of this element */
    private final Set<Integer> unusedBits;

    /**
     * Constructor for the ElementInfo enum
     *
     * @param numberCount The number of 254-bit numbers contained in this element
     * @param hasFlags    Whether this element contains flags in the last number
     * @param group       The group of the element, if it is a group element
     */
    ArkworksSerializationInfo(final int numberCount, final boolean hasFlags, @Nullable final AltBN128CurveGroup group) {
        this.numberCount = numberCount;
        this.hasFlags = hasFlags;
        this.group = group;

        final Set<Integer> unusedBits = new HashSet<>();
        for (int i = 1; i <= numberCount; i++) {
            // if we have flags, the last number will contain the flags
            if (hasFlags && i == numberCount) {
                continue;
            }
            // the last 2 bits of each number are unused, or they are flags
            unusedBits.add(NUMBER_SIZE_BYTES * Byte.SIZE * i - 1);
            unusedBits.add(NUMBER_SIZE_BYTES * Byte.SIZE * i - 2);
        }
        this.unusedBits = Collections.unmodifiableSet(unusedBits);
    }

    public static ArkworksSerializationInfo fromGroup(final AltBN128CurveGroup group) {
        return switch (group) {
            case GROUP1 -> GROUP1_ELEMENT;
            case GROUP2 -> GROUP2_ELEMENT;
        };
    }

    /**
     * Get the number of 254-bit numbers contained in this element
     *
     * @return The number of 254-bit numbers contained in this element
     */
    @SuppressWarnings("unused")
    public int getNumberCount() {
        return numberCount;
    }

    /**
     * Get whether this element contains flags in the last number
     *
     * @return Whether this element contains flags in the last number
     */
    public boolean hasFlags() {
        return hasFlags;
    }

    /**
     * Get the group of the element, if it is a group element
     *
     * @return The group of the element, if it is a group element
     */
    public @NonNull AltBN128CurveGroup getGroup() {
        return Optional.of(group).orElseThrow();
    }

    /**
     * Get the set of bits that are unused in the serialization of this element
     *
     * @return The set of bits that are unused in the serialization of this element
     */
    public Set<Integer> getUnusedBits() {
        return unusedBits;
    }

    /**
     * Get the number of bits used to serialize this element
     *
     * @return The number of bits used to serialize this element
     */
    public int numberOfBits() {
        return NUMBER_SIZE_BYTES * Byte.SIZE * numberCount;
    }

    /**
     * Get the bit index of the Y coordinate flag
     *
     * @return the index of the flag
     */
    public int getYCoordinateFlagBitIndex() {
        return NUMBER_SIZE_BYTES * Byte.SIZE * numberCount - 1 - BIT_FLAG_Y_COORDINATE_POSITION;
    }

    /**
     * Get the bit index of the zero element flag
     *
     * @return the index of the flag
     */
    public int getZeroFlagBitIndex() {
        return NUMBER_SIZE_BYTES * Byte.SIZE * numberCount - 1 - BIT_FLAG_ZERO_POSITION;
    }

    public boolean isZeroElement(final byte[] bytes) {
        return (bytes[bytes.length - 1] & MASK_ZERO) == MASK_ZERO;
    }

    public boolean isYSmaller(final byte[] bytes) {
        return (bytes[bytes.length - 1] & MASK_Y_COORDINATE) == MASK_Y_COORDINATE;
    }
}
