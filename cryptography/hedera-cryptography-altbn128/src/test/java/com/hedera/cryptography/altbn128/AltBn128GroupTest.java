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

package com.hedera.cryptography.altbn128;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@WithRng
class AltBn128GroupTest {
    @Test
    void constructionSucceeds() {
        assertDoesNotThrow(() -> new AltBn128Group(AltBN128CurveGroup.GROUP2));
    }

    @Test
    void createGroupElementZeroIsNotNull() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        assertNotNull(group.zero());
    }

    @Test
    void createGroupElementGeneratorIsNotNull() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        assertNotNull(group.generator());
    }

    @Test
    void createRandomGroupElementIsNotNull(final Random rng) {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        final byte[] seed = new byte[group.seedSize()];
        rng.nextBytes(seed);
        assertNotNull(group.random(seed));
    }

    @Test
    void createRandomGroupWithSmallerSeedThrowsException() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        final byte[] smallerSeed = new byte[group.seedSize() - 1];
        final byte[] largerSeed = new byte[group.seedSize() + 1];
        assertThrows(IllegalArgumentException.class, () -> group.random(smallerSeed));
        assertThrows(IllegalArgumentException.class, () -> group.random(largerSeed));
    }

    @Test
    void createGroupElementFromRandomIsNotNull(final Random rng) {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        ByteBuffer buffer = ByteBuffer.allocate(group.seedSize());
        rng.nextBytes(buffer.array());
        group.random(buffer.array());
        assertNotNull(buffer.array());
    }

    @Test
    void createGroupElementHashToCurveIsNotNull(final Random rng) {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        final byte[] message = new byte[1024];
        rng.nextBytes(message);

        assertNotNull(group.hashToCurve(message));
    }

    @Test
    void createRandomGroupElementAndToBytesIsNotNull(final Random rng) {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        final byte[] seed = new byte[group.seedSize()];
        rng.nextBytes(seed);
        final GroupElement random = group.random(seed);
        assertNotNull(random);
        assertNotNull(random.toBytes());
    }

    @SuppressWarnings("EqualsWithItself")
    @Test
    void equalityTest() {
        var group1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        var group2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        assertEquals(new AltBn128Group(AltBN128CurveGroup.GROUP2), group2);
        assertEquals(group2, group2);
        assertNotEquals(group1, group2);
        assertNotEquals(group1, new Object());
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void batchOps(AltBN128CurveGroup gr) {
        var group = new AltBn128Group(gr);
        var field = new AltBn128Field();
        List<FieldElement> scalars =
                IntStream.range(0, 100).boxed().map(field::fromLong).toList();
        List<GroupElement> results = new ArrayList<>();
        assertDoesNotThrow(() -> results.addAll(group.batchMultiply(scalars)));

        assertThrows(
                IllegalArgumentException.class,
                () -> group.batchMultiply(List.of(field.zero(), mock(FieldElement.class))));
        assertThrows(IllegalArgumentException.class, () -> group.add(List.of(group.zero(), mock(GroupElement.class))));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testIdentityProperty(AltBN128CurveGroup gr) {
        var group = new AltBn128Group(gr);
        var generator = group.generator();
        var zero = group.zero();

        // Check if G + 0 = G
        assertEquals(generator, generator.add(zero));
        assertEquals(generator, zero.add(generator));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testAdditionAssociativity(AltBN128CurveGroup gr) {
        var group = new AltBn128Group(gr);
        var G1 = group.generator();
        var G2 = G1.add(G1); // e.g., 2 * G
        var G3 = G1.add(G2); // e.g., 3 * G

        // Check (G1 + G2) + G3 = G1 + (G2 + G3)
        assertEquals(G1.add(G2).add(G3), G1.add(G2.add(G3)));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testAdditionCommutativity(AltBN128CurveGroup gr) {
        var group = new AltBn128Group(gr);
        var G1 = group.generator();
        var G2 = G1.add(G1); // e.g., 2 * G

        // Check G1 + G2 = G2 + G1
        assertEquals(G1.add(G2), G2.add(G1));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testSerializationConsistency(AltBN128CurveGroup gr) {
        var group = new AltBn128Group(gr);
        var element = group.generator();
        byte[] bytes = element.toBytes();
        var deserializedElement = group.fromBytes(bytes);

        assertEquals(element, deserializedElement); // Ensures consistency after serialization
    }

    @Test
    void hashToCurveConsistency(final Random rng) {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        final byte[] message = new byte[1024];
        rng.nextBytes(message);

        var element1 = group.hashToCurve(message);
        var element2 = group.hashToCurve(message);

        assertEquals(element1, element2); // Consistent mapping of input to output
    }

    @Test
    void invalidFromBytesInput() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        assertThrows(IllegalArgumentException.class, () -> group.fromBytes(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> group.fromBytes(new byte[group.elementSize() + 1]));
    }
}
