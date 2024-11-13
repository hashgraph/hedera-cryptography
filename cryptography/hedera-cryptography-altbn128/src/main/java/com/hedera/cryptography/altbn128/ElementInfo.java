package com.hedera.cryptography.altbn128;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public enum ElementInfo {
    FIELD_ELEMENT(1, false, null),
    GROUP1_ELEMENT(2, true, AltBN128CurveGroup.GROUP1),
    GROUP2_ELEMENT(4, true, AltBN128CurveGroup.GROUP2);

    /**
     * The size of each number in bytes. Note: the numbers are actually 254-bit, so the last 2 bits are either
     * unused or used for flags.
     */
    private static final int NUMBER_SIZE_BYTES = 32;
    private static final int BIT_FLAG_Y_COORDINATE_POSITION = 1;
    private static final int BIT_FLAG_ZERO_POSITION = 2;

    private final int numberCount;
    private final boolean hasFlags;
    private final AltBN128CurveGroup group;
    private final Set<Integer> unusedBits;

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

    public int getNumberCount() {
        return numberCount;
    }

    public boolean hasFlags() {
        return hasFlags;
    }


    public @NonNull AltBN128CurveGroup getGroup() {
        return Optional.of(group).orElseThrow();
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
