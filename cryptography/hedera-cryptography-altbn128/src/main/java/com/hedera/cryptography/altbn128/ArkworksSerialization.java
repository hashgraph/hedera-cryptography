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

import static com.hedera.cryptography.utils.ByteArrayUtils.copyAndReverse;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * This enum contains Arkworks serialization information about the different types of elements that can be used in the
 * AltBN128 curve. Each element has a number of 254-bit numbers, and optionally flags in the last number.
 */
public enum ArkworksSerialization {
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
    /** The bit mask for the Y coordinate flag */
    private static final byte MASK_Y_COORDINATE = (byte) 0b10000000;
    /** The bit mask for the zero element flag */
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
    ArkworksSerialization(final int numberCount, final boolean hasFlags, @Nullable final AltBN128CurveGroup group) {
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

    /**
     * Get the serialization information for a group
     *
     * @param group The group
     * @return The serialization information
     */
    @NonNull
    @SuppressWarnings("unused")
    public static ArkworksSerialization fromGroup(@NonNull final AltBN128CurveGroup group) {
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
    @NonNull
    public AltBN128CurveGroup getGroup() {
        return Optional.of(group).orElseThrow();
    }

    /**
     * Get the set of bits that are unused in the serialization of this element
     *
     * @return The set of bits that are unused in the serialization of this element
     */
    @NonNull
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

    /**
     * Checks if this element is a zero element
     *
     * @param bytes the Arkworks serialized bytes
     * @return true if the element is a zero element, false otherwise
     */
    public static boolean isZeroFlagSet(@NonNull final byte[] bytes) {
        return (bytes[bytes.length - 1] & MASK_ZERO) == MASK_ZERO;
    }

    /**
     * Checks if the Y coordinate is negative flag is set
     *
     * @param bytes the Arkworks serialized bytes
     * @return true if the Y coordinate flag is set, false otherwise
     */
    public static boolean isYNegativeFlagSet(@NonNull final byte[] bytes) {
        return (bytes[bytes.length - 1] & MASK_Y_COORDINATE) == MASK_Y_COORDINATE;
    }

    /**
     * Sets or clears the Y coordinate negative flag in the Arkworks serialized bytes.
     *
     * @param bytes the Arkworks serialized bytes
     * @param set   true to set the flag, false to clear it
     */
    public static void setYNegativeFlag(@NonNull final byte[] bytes, boolean set) {
        if (set) {
            // Set the flag using bitwise OR
            bytes[bytes.length - 1] |= MASK_Y_COORDINATE;
        } else {
            // Clear the flag using bitwise AND with the negated mask
            bytes[bytes.length - 1] &= ~MASK_Y_COORDINATE;
        }
    }

    /**
     * Removes the flags from this serialized element
     *
     * @param bytes the Arkworks serialized bytes
     * @param flagsIndex which flag to clean
     */
    public static void removeFlags(@NonNull final byte[] bytes, final int flagsIndex) {
        bytes[flagsIndex] = (byte) (bytes[flagsIndex] & 0b00111111);
    }

    /**
     * Get the X or Y coordinate from the serialized bytes
     *
     * @param bytes the Arkworks serialized bytes
     * @param isX   true if the X coordinate is requested, false if the Y coordinate is requested
     * @return the X or Y coordinate
     */
    @NonNull
    public static List<BigInteger> getCoordinate(@NonNull final byte[] bytes, final boolean isX) {
        final int from = isX ? 0 : bytes.length / 2;
        final int to = isX ? bytes.length / 2 : bytes.length;
        final List<BigInteger> list = new ArrayList<>();
        for (int i = from; i < to; i += NUMBER_SIZE_BYTES) {
            final byte[] copy = new byte[NUMBER_SIZE_BYTES];
            copyAndReverse(bytes, i, copy, 0, NUMBER_SIZE_BYTES);
            removeFlags(copy, 0);
            list.add(new BigInteger(copy));
        }
        return list;
    }

    /**
     * Creates a byte array from a list of BigInteger values
     *
     * @param coordinates all the coordinates elements
     * @return the serialized bytes in arkworks format
     */
    @NonNull
    public static byte[] coordinatesToBytes(@NonNull final List<BigInteger> coordinates) {
        Objects.requireNonNull(coordinates, "coordinates must not be null");
        final byte[] bytes = new byte[NUMBER_SIZE_BYTES * coordinates.size()];
        for (int i = 0; i < coordinates.size(); i++) {
            final BigInteger bi = coordinates.get(i);
            final byte[] biArray = bi.toByteArray();
            if (biArray.length > NUMBER_SIZE_BYTES) {
                throw new IllegalArgumentException("BigInteger is too large to fit in a 254-bit number");
            }
            copyAndReverse(biArray, 0, bytes, i * NUMBER_SIZE_BYTES, biArray.length);
        }
        return bytes;
    }
}
