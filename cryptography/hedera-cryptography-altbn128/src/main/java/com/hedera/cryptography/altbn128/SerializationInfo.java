package com.hedera.cryptography.altbn128;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public enum SerializationInfo {
    FIELD_ELEMENT(1, false),
    GROUP1_ELEMENT(2, true),
    GROUP2_ELEMENT(4, true);

    /**
     * The size of each number in bytes. Note: the numbers are actually 254-bit, so the last 2 bits are either
     * unused or used for flags.
     */
    private static final int NUMBER_SIZE_BYTES = 32;
    private static final int BIT_FLAG_Y_COORDINATE_POSITION = 1;
    private static final int BIT_FLAG_ZERO_POSITION = 2;

    private final int numberCount;
    private final boolean hasFlags;
    private final Set<Integer> unusedBits;

    SerializationInfo(final int numberCount, final boolean hasFlags) {
        this.numberCount = numberCount;
        this.hasFlags = hasFlags;

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

    public int getNumberCount() {
        return numberCount;
    }

    public boolean hasFlags() {
        return hasFlags;
    }

    public Set<Integer> getUnusedBits() {
        return unusedBits;
    }

    public int getYCoordinateFlagBitIndex(){
        return NUMBER_SIZE_BYTES * Byte.SIZE * numberCount - BIT_FLAG_Y_COORDINATE_POSITION;
    }

    public int getZeroFlagBitIndex(){
        return NUMBER_SIZE_BYTES * Byte.SIZE * numberCount - BIT_FLAG_ZERO_POSITION;
    }
}
