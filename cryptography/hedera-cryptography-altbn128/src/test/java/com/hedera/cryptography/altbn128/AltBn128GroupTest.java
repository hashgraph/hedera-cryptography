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

import com.hedera.common.testfixtures.WithRng;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
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
    void createGroupElementFromHashIsNotNull(final Random rng) {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        final byte[] message = new byte[1024];
        rng.nextBytes(message);

        assertNotNull(group.fromHash(message));
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

    @Test
    @SuppressWarnings("EqualsWithItself")
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
        assertThrows(
                IllegalArgumentException.class, () -> group.batchAdd(List.of(group.zero(), mock(GroupElement.class))));
    }
}
