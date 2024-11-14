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
public enum ElementInfo {
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
    ElementInfo(final int numberCount, final boolean hasFlags, @Nullable final AltBN128CurveGroup group) {
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
}
