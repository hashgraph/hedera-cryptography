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

package com.hedera.cryptography.altbn128.common;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Static utility {@link BigInteger} operations */
public class BigIntegerUtils {


    /**
     * Converts a BigInteger into a byte array of the given size in little-endian order.
     *
     * @param value the BigInteger to convert
     * @param size  the size of the output byte array
     * @return a byte array of the specified size representing the BigInteger in little-endian order
     * @throws NullPointerException if the BigInteger is null
     * @throws IllegalArgumentException if the BigInteger cannot be represented in the specified size
     */
    @NonNull
    public static byte[] toLittleEndianBytes(@NonNull final BigInteger value, final int size) {
        byte[] bigEndianBytes =
                Objects.requireNonNull(value, "value must not be null").toByteArray();
        if (bigEndianBytes.length > size) {
            throw new IllegalArgumentException("BigInteger cannot be represented in " + size + " bytes.");
        }

        byte[] paddedBytes = new byte[size];

        System.arraycopy(bigEndianBytes, 0, paddedBytes, size - bigEndianBytes.length, bigEndianBytes.length);

        return reverseBytes(paddedBytes);
    }
    /**
     * Converts a variable number of BigInteger arguments to their byte array representations,
     * reverses each byte array, and concatenates them into a single byte array.
     *
     * @param args a variable number of BigInteger arguments
     * @return a concatenated byte array containing the reversed byte array representations of each BigInteger
     */
    @NonNull
    public static byte[] toLittleEndianBytes(final int size, @NonNull final BigInteger... args) {
        int totalSize = 0;
        ByteBuffer buffer = ByteBuffer.allocate(size);

        for (BigInteger arg : args) {
            totalSize += arg.toByteArray().length;

            if (totalSize > size) {
                break;
            }

            byte[] byteArray = arg.toByteArray();
            byte[] reversedByteArray = reverseBytes(byteArray);

            buffer.put(reversedByteArray);
        }
        if (totalSize > size) {
            throw new IllegalArgumentException("BigInteger cannot be represented in " + size + " bytes.");
        }

        return buffer.array();
    }

    /**
     * Splits a byte array into chunks of a given size, reverses each chunk, and converts each reversed chunk to a BigInteger.
     *
     * @param byteArray the byte array to be split and processed
     * @param chunkSize the size of each chunk
     * @return a list of BigIntegers created from the reversed chunks of the byte array
     * @throws IllegalArgumentException if the byte array length is not divisible by the chunk size
     */
    @NonNull
    public static List<BigInteger> toBigIntegers(final @NonNull byte[] byteArray, int chunkSize) {
        if (byteArray.length % chunkSize != 0) {
            throw new IllegalArgumentException("Byte array length must be divisible by the chunk size.");
        }

        List<BigInteger> bigIntegers = new ArrayList<>();

        for (int i = 0; i < byteArray.length; i += chunkSize) {
            byte[] chunk = Arrays.copyOfRange(byteArray, i, i + chunkSize);
            byte[] reversedChunk = reverseBytes(chunk);

            BigInteger bigInteger = new BigInteger(reversedChunk);
            bigIntegers.add(bigInteger);
        }

        return bigIntegers;
    }
    /**
     * Converts a little-endian byte array into a BigInteger.
     *
     * @param littleEndianBytes the byte array in little-endian order
     * @return the corresponding BigInteger
     */
    @NonNull
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
    @NonNull
    private static byte[] reverseBytes(@NonNull byte[] input) {
        for (int i = 0; i < input.length / 2; i++) {
            byte temp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = temp;
        }
        return input;
    }
}
