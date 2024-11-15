package com.hedera.cryptography.utils.test.fixtures;

import edu.umd.cs.findbugs.annotations.NonNull;

public class ByteUtils {
    /**
     * Creates a binary string representation of the following byte array
     * @param bytes the byte array to represent
     * @return a string representation of the byte array
     */
    @SuppressWarnings("unused")// useful for debugging
    public static @NonNull String toBinaryString(@NonNull final byte[] bytes) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : bytes) {
            sb.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
            sb.append(' ');
        }
        return sb.toString();
    }
}
