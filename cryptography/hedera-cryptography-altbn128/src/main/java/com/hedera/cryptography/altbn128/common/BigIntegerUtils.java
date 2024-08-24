package com.hedera.cryptography.altbn128.common;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/** Static utility {@link BigInteger} operations */
public class BigIntegerUtils {

    /** Hidden Constructor */
    private BigIntegerUtils() {}

    /**
     * Converts a BigInteger into a byte array of the given size in little-endian order.
     *
     * @param value the BigInteger to convert
     * @param size  the size of the output byte array
     * @return a byte array of the specified size representing the BigInteger in little-endian order
     * @throws NullPointerException if the BigInteger is null
     * @throws IllegalArgumentException if the BigInteger cannot be represented in the specified size
     */
    public static byte[] toLittleEndianBytes(@NonNull final BigInteger value, final int size) {
        byte[] bigEndianBytes = Objects.requireNonNull(value, "value must not be null").toByteArray();
        if (bigEndianBytes.length > size) {
            throw new IllegalArgumentException("BigInteger cannot be represented in " + size + " bytes.");
        }

        byte[] paddedBytes = new byte[size];

        System.arraycopy(bigEndianBytes, 0, paddedBytes, size - bigEndianBytes.length, bigEndianBytes.length);

        return reverseBytes(paddedBytes);
    }

    /**
     * Converts a little-endian byte array into a BigInteger.
     *
     * @param littleEndianBytes the byte array in little-endian order
     * @return the corresponding BigInteger
     */
    public static BigInteger fromLittleEndianBytes(@NonNull final byte[] littleEndianBytes) {
        Objects.requireNonNull(littleEndianBytes, "littleEndianBytes must not be null");
        byte[] bigEndianBytes = reverseBytes(Arrays.copyOf(littleEndianBytes, littleEndianBytes.length));
        return new BigInteger(bigEndianBytes);
    }

    /**
     * Reverses the order of bytes in the array.
     *
     * @param input the byte array to reverse
     * @return the reversed byte array
     */
    private static byte[] reverseBytes(@NonNull byte[] input) {
        for (int i = 0; i < input.length / 2; i++) {
            byte temp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = temp;
        }
        return input;
    }


}
