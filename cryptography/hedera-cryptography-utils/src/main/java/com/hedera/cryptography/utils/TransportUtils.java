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
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Utility class providing serialization and deserialization functionality for transporting data.
 */
public class TransportUtils {

    /**
     * A utility class for serializing various data types into a byte array.
     */
    public static class Serializer {
        private final Queue<byte[]> entries = new LinkedList<>();
        private int size = 0;

        /**
         * Adds the content of a supplied byte array to the serializer.
         *
         * @param byteProvider A supplier that provides the byte array to be added.
         * @return The Serializer instance for method chaining.
         */
        @NonNull
        public Serializer put(@NonNull final Supplier<byte[]> byteProvider) {
            var z = byteProvider.get();
            size += z.length;
            entries.offer(z);
            return this;
        }

        /**
         * Serializes a list of elements using the provided serializer function for each element.
         *It assumes that the serialized version of each element in the list have the same size.
         *
         * @param <T> The type of elements in the list.
         * @param list The list of elements to serialize.
         * @param serializer A function that serializes each element into a byte array.
         * @return The Serializer instance for method chaining.
         */
        @NonNull
        public <T> Serializer putListSameSize(
                @NonNull final List<T> list, @NonNull final Function<T, byte[]> serializer) {
            var totalSize = Objects.requireNonNull(list).size();
            Objects.requireNonNull(serializer);
            put(totalSize);
            for (var entry : list) {
                var bEntry = serializer.apply(entry);
                size += bEntry.length;
                entries.offer(bEntry);
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
            size++;
            entries.offer(new byte[] {value});
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
            size += Integer.BYTES;
            entries.offer(
                    new byte[] {(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value});
            return this;
        }

        /**
         * Serializes all added entries into a byte array.
         *
         * @return The byte array containing the serialized data.
         */
        @NonNull
        public byte[] toBytes() {
            if (size >= 0 && entries.isEmpty()) {
                throw new IllegalStateException("Already consumed");
            }
            var buffer = ByteBuffer.allocate(size);
            for (var entry : entries) {
                buffer.put(entry);
            }
            entries.clear();
            return buffer.array();
        }
    }

    /**
     * A utility class for deserializing data from a byte array.
     */
    public static class Deserializer {

        private final ByteBuffer buffer;

        /**
         * Constructs a Deserializer with the given byte array.
         *
         * @param bytes The byte array containing serialized data.
         */
        public Deserializer(@NonNull byte[] bytes) {
            this.buffer = ByteBuffer.wrap(Objects.requireNonNull(bytes, "bytes cannot be null"))
                    .asReadOnlyBuffer();
        }

        /**
         * Deserializes the specified size in the byte array using the provided function if there is enough information in the buffer.
         *
         * @param <T> The type of the deserialized object.
         * @param f The function to convert a byte array into an object of type T.
         * @param size The number of bytes to read.
         * @return The deserialized object.
         * @throws IllegalStateException if there are not enough bytes remaining to read.
         */
        @NonNull
        public <T> T read(@NonNull final Function<byte[], T> f, int size) {
            canRead(size);
            var bytes = new byte[size];
            buffer.get(bytes);
            return Objects.requireNonNull(f).apply(bytes);
        }

        private void canRead(final int size) {
            if (buffer.remaining() < size) {
                throw new IllegalStateException("Not enough bytes to read");
            }
        }

        /**
         * Reads and deserializes a byte from the buffer if there is enough information in the buffer.
         *
         * @return The deserialized byte value.
         * @throws IllegalStateException if there are not enough bytes to read.
         */
        public byte readByte() {
            canRead(Byte.BYTES);
            return buffer.get();
        }

        /**
         * Reads and deserializes an int from the buffer if there is enough information in the buffer.
         *
         * @return The deserialized integer value.
         * @throws IllegalStateException if there are not enough bytes to read.
         */
        public int readInt() {
            canRead(Integer.BYTES);
            return buffer.getInt();
        }

        /**
         * Deserializes a list of elements using the provided function and specified size for each element.
         *
         * @param <T> The type of elements in the list.
         * @param f The function that converts a byte array into an object of type T.
         * @param size The byte size of each element.
         * @return The list of deserialized objects.
         * @throws IllegalStateException if there are not enough bytes to read.
         */
        @NonNull
        public <T> List<T> readListSameSize(@NonNull final Function<byte[], T> f, final int size) {
            canRead(Integer.BYTES);
            var elements = readInt();
            canRead(elements * size);
            var list = new ArrayList<T>(elements);
            while (elements > 0) {
                list.add(read(f, size));
                elements--;
            }
            return list;
        }
    }
}
