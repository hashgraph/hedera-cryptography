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

package com.hedera.cryptography.utils;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

/** Static utility {@link Byte[]} operations */
public class ByteArrayUtils {

    /**
     * private constructor to ensure static access
     */
    private ByteArrayUtils() {
        // private constructor to ensure static access
    }

    /**
     * Converts a BigInteger into a byte array in little-endian order.
     *
     * @param value the BigInteger to convert
     * @return a byte array of the representing the BigInteger in little-endian order
     * @throws NullPointerException if the BigInteger is null
     */
    @NonNull
    public static byte[] toLittleEndianBytes(@NonNull final BigInteger value) {
        final byte[] bigEndianBytes =
                Objects.requireNonNull(value, "value must not be null").toByteArray();

        return reverseBytesInPlace(bigEndianBytes);
    }

    /**
     * Converts a variable number of BigInteger arguments to their byte array representations, reverses each byte array,
     * and concatenates them into a single byte array.
     *
     * @param size the desired final length of the resulting byte array
     * @param args a variable number of BigInteger arguments
     * @return a concatenated byte array containing the reversed byte array representations of each BigInteger
     */
    @NonNull
    public static byte[] toLittleEndianBytes(final int size, @NonNull final BigInteger... args) {
        int totalSize = 0;
        final ByteBuffer buffer = ByteBuffer.allocate(size);

        for (final BigInteger arg : args) {
            final byte[] bigInt = arg.toByteArray();
            totalSize += bigInt.length;

            if (totalSize > size) {
                break;
            }

            final byte[] padded = Arrays.copyOf(bigInt, size / args.length);

            buffer.put(reverseBytesInPlace(padded));
        }
        if (totalSize > size) {
            throw new IllegalArgumentException("BigInteger cannot be represented in " + size + " bytes.");
        }

        return buffer.array();
    }

    /**
     * Reverses the order of bytes in the array. Note: this method modifies the input array in place.
     *
     * @param array the byte array to reverse
     * @return the reversed byte array
     */
    @NonNull
    public static byte[] reverseBytesInPlace(@NonNull final byte[] array) {
        return reverseBytesInPlace(array, 0, array.length);
    }

    /**
     * Reverses the order of bytes in the array. Note: this method modifies the input array in place.
     *
     * @param array the byte array to reverse
     * @param start the index from which to start reversing
     * @param end   the index at which to stop reversing
     * @return the reversed byte array
     */
    @NonNull
    public static byte[] reverseBytesInPlace(@NonNull final byte[] array, final int start, final int end) {
        final int iLimit = start + (end - start) / 2;
        for (int i = start; i < iLimit; i++) {
            final int j = end - (i - start) - 1;
            final byte tmp = array[i];
            array[i] = array[j];
            array[j] = tmp;
        }
        return array;
    }

    /**
     * Copies a range of bytes from the source array to the destination array in reverse order.
     *
     * @param source  the source array
     * @param srcPos  the starting position in the source array
     * @param dest    the destination array
     * @param destPos the starting position in the destination array
     * @param length  the number of bytes to copy
     */
    public static void copyAndReverse(
            @NonNull final byte[] source,
            final int srcPos,
            @NonNull final byte[] dest,
            final int destPos,
            final int length) {
        if (srcPos < 0 || srcPos + length > source.length) {
            throw new IllegalArgumentException("Invalid source range");
        }
        if (destPos < 0 || destPos + length > dest.length) {
            throw new IllegalArgumentException("Invalid destination range");
        }
        for (int i = 0; i < length; i++) {
            dest[destPos + i] = source[srcPos + length - 1 - i];
        }
    }

    /**
     * Transforms an integer value into a byte array
     *
     * @param value the integer to transform
     * @return the resulting byte array
     */
    @NonNull
    public static byte[] toByteArray(final int value) {
        return new byte[] {(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
    }

    /**
     * Returns a byte[] as an unsigned int[].
     * Each element of the origina array is transformed used  {@link Byte#toUnsignedInt(byte)}
     * @param bytes the original byte array to reinterpret.
     * @return the reinterpreted array as unsigned values
     */
    public static @NonNull int[] unsigned(final @NonNull byte[] bytes) {
        final int[] result = new int[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            result[i] = Byte.toUnsignedInt(bytes[i]);
        }
        return result;
    }

    /**
     * Creates a byte array from an unsigned representation of int values
     * @param bytes the individual values
     * @return a byte[] array represented
     * @throws IllegalArgumentException if any of the values is negative or out of range to be represented by a byte
     */
    public static @NonNull byte[] fromUnsigned(final @NonNull int... bytes) {
        final byte[] result = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] < 0 || bytes[i] > 255) {
                throw new IllegalArgumentException();
            }
            result[i] = (byte) (bytes[i] & 0xFF);
        }
        return result;
    }

    /**
     * A utility class for serializing various data types into a byte array.
     */
    public static class Serializer {
        private final ByteArrayOutputStream bo;
        private final DataOutputStream os;

        /**
         * Constructs a utility class for serializing various data types into a byte array.
         */
        public Serializer() {
            this.bo = new ByteArrayOutputStream();
            this.os = new DataOutputStream(bo);
        }

        /**
         * Adds the content of a supplied byte array to the serializer.
         *
         * @param byteProvider A supplier that provides the byte array to be added.
         * @return The Serializer instance for method chaining.
         */
        @NonNull
        public Serializer put(@NonNull final Supplier<byte[]> byteProvider) {
            final var z = byteProvider.get();

            try {
                os.write(z);
            } catch (final IOException e) {
                throw new IllegalStateException("Could not write", e);
            }
            return this;
        }

        /**
         * Serializes a list of elements using the provided serializer function for each element. It assumes that the
         * serialized version of each element in the list have the same size.
         *
         * @param <T>        The type of elements in the list.
         * @param list       The list of elements to serialize.
         * @param serializer A function that serializes each element into a byte array.
         * @return The Serializer instance for method chaining.
         */
        @NonNull
        public <T> Serializer putListSameSize(
                @NonNull final List<T> list, @NonNull final Function<T, byte[]> serializer) {
            Objects.requireNonNull(serializer);
            for (final var entry : list) {
                try {
                    os.write(serializer.apply(entry));
                } catch (final IOException e) {
                    throw new IllegalStateException("Could not write", e);
                }
            }
            return this;
        }

        /**
         * Adds a byte value to the serializer.
         *
         * @param value The byte value to serialize.
         * @return The Serializer instance for method chaining.
         */
        @NonNull
        public Serializer put(final byte value) {
            try {
                os.write(value);
            } catch (final IOException e) {
                throw new IllegalStateException("Could not write", e);
            }
            return this;
        }

        /**
         * Adds an integer value to the serializer.
         *
         * @param value The integer value to serialize.
         * @return The Serializer instance for method chaining.
         */
        @NonNull
        public Serializer put(final int value) {
            try {
                os.write(toByteArray(value));
            } catch (final IOException e) {
                throw new IllegalStateException("Could not write", e);
            }
            return this;
        }

        /**
         * Serializes all added entries into a byte array.
         *
         * @return The byte array containing the serialized data.
         */
        @NonNull
        public byte[] toBytes() {
            return bo.toByteArray();
        }
    }

    /**
     * A utility class for deserializing data from a byte array.
     */
    public static class Deserializer {
        private final DataInputStream is;

        /**
         * Constructs a Deserializer with the given byte array.
         *
         * @param message The byte array containing serialized data.
         */
        public Deserializer(@NonNull final byte[] message) {
            Objects.requireNonNull(message, "message must not be null");
            final ByteArrayInputStream buffer = new ByteArrayInputStream(message);
            this.is = new DataInputStream(buffer);
        }

        /**
         * Deserializes the specified size in the byte array using the provided function if there is enough information
         * in the buffer.
         *
         * @param <T>  The type of the deserialized object.
         * @param f    The function to convert a byte array into an object of type T.
         * @param size The number of bytes to read.
         * @return The deserialized object.
         * @throws IllegalStateException if there are not enough bytes remaining to read.
         */
        @NonNull
        public <T> T read(@NonNull final Function<byte[], T> f, final int size) {
            final var bytes = new byte[size];
            try {
                if (is.read(bytes) != size) {
                    throw new IllegalStateException("Not enough bytes to read");
                }
                return Objects.requireNonNull(f).apply(bytes);
            } catch (final Exception e) {
                throw new IllegalStateException("Cannot read", e);
            }
        }

        /**
         * Reads and deserializes a byte from the buffer if there is enough information in the buffer.
         *
         * @return The deserialized byte value.
         * @throws IllegalStateException if there are not enough bytes to read.
         */
        public byte readByte() {
            try {
                return is.readByte();
            } catch (final IOException e) {
                throw new IllegalStateException("Cannot read", e);
            }
        }

        /**
         * Reads and deserializes an int from the buffer if there is enough information in the buffer.
         *
         * @return The deserialized integer value.
         * @throws IllegalStateException if there are not enough bytes to read.
         */
        public int readInt() {
            try {
                return is.readInt();
            } catch (final IOException e) {
                throw new IllegalStateException("Cannot Read", e);
            }
        }

        /**
         * Deserializes a list of elements using the provided function and specified elementSize for each element.
         *
         * @param <T>         The type of elements in the list.
         * @param f           The function that converts a byte array into an object of type T.
         * @param listSize    The number of elements in the list.
         * @param elementSize The size in bytes of each element.
         * @return The list of deserialized objects.
         * @throws IllegalStateException if there are not enough bytes to read.
         */
        @NonNull
        public <T> List<T> readListSameSize(
                @NonNull final Function<byte[], T> f, final int listSize, final int elementSize) {
            var elems = listSize;
            final var list = new ArrayList<T>(elems);
            while (elems > 0) {
                list.add(read(f, elementSize));
                elems--;
            }
            return list;
        }
    }
}
