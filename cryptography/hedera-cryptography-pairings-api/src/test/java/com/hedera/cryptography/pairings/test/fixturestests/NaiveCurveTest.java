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

package com.hedera.cryptography.pairings.test.fixturestests;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.*;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveGroup;
import com.hedera.cryptography.pairings.test.fixtures.curve.NaiveGroupElement;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class NaiveCurveTest {
    private Group group;

    @BeforeEach
    void setUp() {
        group = new NaiveGroup(new NaiveCurve());
    }

    @Test
    void testGenerator() {
        final GroupElement generator = group.generator();
        assertNotNull(generator, "Generator should not be null");
        assertEquals(group, generator.getGroup(), "Generator should belong to the group");
    }

    @Test
    void testZeroElement() {
        final GroupElement zeroElement = group.zero();
        assertNotNull(zeroElement, "Zero element should not be null");
        assertEquals(
                BigInteger.ZERO, ((NaiveGroupElement) zeroElement).value(), "Zero element should have a value of 0");
    }

    @Test
    void testRandomElement() {
        final GroupElement randomElement1 = group.random(new Random());
        final GroupElement randomElement2 = group.random(new Random());

        assertNotNull(randomElement1, "Random element 1 should not be null");
        assertNotNull(randomElement2, "Random element 2 should not be null");
        assertNotEquals(
                randomElement1.toBytes(),
                randomElement2.toBytes(),
                "Random elements should not be equal due to randomness");
    }

    @Test
    void testBatchAdd() {
        final GroupElement element1 = group.generator();
        final GroupElement element2 = group.random(new Random());

        final Collection<GroupElement> elements = Arrays.asList(element1, element2);
        final GroupElement sum = group.batchAdd(elements);

        assertNotNull(sum, "Sum of batch add should not be null");

        final BigInteger expectedSum = ((NaiveGroupElement) element1)
                .value()
                .add(((NaiveGroupElement) element2).value())
                .mod(BigInteger.valueOf(23));
        assertEquals(
                expectedSum,
                ((NaiveGroupElement) sum).value(),
                "Batch add result should be the sum of individual elements modulo the group prime");
    }

    @Test
    void testFromBytes() {
        final GroupElement generator = group.generator();
        final byte[] generatorBytes = generator.toBytes();

        final GroupElement deserializedElement = group.fromBytes(generatorBytes);

        assertNotNull(deserializedElement, "Deserialized element should not be null");
        assertArrayEquals(
                generator.toBytes(),
                deserializedElement.toBytes(),
                "Serialized and deserialized element bytes should match");
    }

    @Test
    void testHashToCurve() {
        final byte[] input = "test input".getBytes();
        final GroupElement hashedElement = group.hashToCurve(input);

        assertNotNull(hashedElement, "Hashed element should not be null");

        final GroupElement hashedElement2 = group.hashToCurve(input);
        assertArrayEquals(
                hashedElement.toBytes(),
                hashedElement2.toBytes(),
                "Hashing the same input should produce the same group element");
    }
}
