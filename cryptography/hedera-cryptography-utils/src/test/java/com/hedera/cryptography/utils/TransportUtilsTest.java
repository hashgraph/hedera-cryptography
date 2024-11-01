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

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.utils.TransportUtils.Deserializer;
import com.hedera.cryptography.utils.TransportUtils.Serializer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class TransportUtilsTest {
    @Test
    void testSingleByteSerialization() {
        Serializer serializer = new Serializer();
        serializer.put((byte) 42);

        Deserializer deserializer = new Deserializer(serializer.toBytes());
        assertEquals(42, deserializer.readByte());
    }

    @Test
    void testSingleIntSerialization() {
        Serializer serializer = new Serializer();
        serializer.put(123456789);

        Deserializer deserializer = new Deserializer(serializer.toBytes());
        assertEquals(123456789, deserializer.readInt());
    }

    @Test
    void testCustomByteArraySerialization() {
        byte[] data = "hello".getBytes(StandardCharsets.UTF_8);

        Serializer serializer = new Serializer();
        serializer.put(() -> data);

        Deserializer deserializer = new Deserializer(serializer.toBytes());
        assertArrayEquals(data, deserializer.read(Function.identity(), data.length));
    }

    @Test
    void testListSerialization() {
        List<String> strings = List.of("apples", "banana", "cherry");
        Serializer serializer = new Serializer();
        serializer.putListSameSize(strings, s -> s.getBytes(StandardCharsets.UTF_8));

        Deserializer deserializer = new Deserializer(serializer.toBytes());
        var deserializedStrings = deserializer.readListSameSize(s -> new String(s, StandardCharsets.UTF_8), 6);

        assertEquals(strings, deserializedStrings);
    }

    @Test
    void testMultipleDataTypesSerialization() {
        Serializer serializer = new Serializer();
        serializer.put(42);
        serializer.put((byte) 13);
        serializer.put(() -> "data".getBytes(StandardCharsets.UTF_8));

        Deserializer deserializer = new Deserializer(serializer.toBytes());
        assertEquals(42, deserializer.readInt());
        assertEquals(13, deserializer.readByte());
        assertArrayEquals("data".getBytes(StandardCharsets.UTF_8), deserializer.read(Function.identity(), 4));
    }

    @Test
    void testSerializationEmptyList() {
        List<String> emptyList = List.of();
        Serializer serializer = new Serializer();
        serializer.putListSameSize(emptyList, s -> s.getBytes(StandardCharsets.UTF_8));

        Deserializer deserializer = new Deserializer(serializer.toBytes());
        List<String> deserializedList =
                deserializer.readListSameSize(bytes -> new String(bytes, StandardCharsets.UTF_8), 0);

        assertTrue(deserializedList.isEmpty());
    }

    @Test
    void testInvalidDeserialization() {
        Serializer serializer = new Serializer();
        serializer.put(42); // Add an integer

        Deserializer deserializer = new Deserializer(serializer.toBytes());
        assertEquals(42, deserializer.readInt());

        // Trying to read beyond the available data should throw an exception
        assertThrows(IllegalStateException.class, deserializer::readByte);
    }

    @Test
    void testCannotReread() {
        Serializer serializer = new Serializer();
        serializer.put((byte) 42);
        serializer.toBytes();
        assertThrows(IllegalStateException.class, serializer::toBytes);
    }
}
