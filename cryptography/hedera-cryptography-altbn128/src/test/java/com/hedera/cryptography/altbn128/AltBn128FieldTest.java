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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

@WithRng
class AltBn128FieldTest {

    @Test
    void constructionSucceeds() {
        Assertions.assertDoesNotThrow(AltBn128Field::new);
    }

    @Test
    void createFieldElementOneIsNotNull() {
        var field = new AltBn128Field();
        assertNotNull(field.one());
    }

    @Test
    void createFieldElementZeroIsNotNull() {
        var field = new AltBn128Field();
        assertNotNull(field.zero());
    }

    @Test
    void zeroNotEqualsOne() {
        var field = new AltBn128Field();
        assertNotEquals(field.zero(), field.one());
        assertNotEquals(field.zero(), field.one());
        assertNotEquals(field.one(), field.zero());
    }

    @Test
    void createRandomFieldElementIsNotNull(final Random rng) {
        var field = new AltBn128Field();
        final byte[] seed = new byte[field.seedSize()];
        rng.nextBytes(seed);
        assertNotNull(field.random(seed));
    }

    @Test
    void createRandomFieldWithSmallerSeedThrowsException() {
        var field = new AltBn128Field();
        final byte[] smallerSeed = new byte[field.seedSize() - 1];
        final byte[] largerSeed = new byte[field.seedSize() + 1];
        assertThrows(IllegalArgumentException.class, () -> field.random(smallerSeed));
        assertThrows(IllegalArgumentException.class, () -> field.random(largerSeed));
    }

    @Test
    void createFieldFromLongIsNotNull(final Random rng) {
        var field = new AltBn128Field();
        var value = rng.nextLong(Long.MAX_VALUE);
        assertNotNull(field.fromLong(value));
    }

    @Test
    void createFieldElementFromNegativeLongMaxValue() {
        var field = new AltBn128Field();
        assertNotNull(field.fromLong(Long.MAX_VALUE));
    }

    @Test
    void createFieldElementFromNegativeLongValueThrowsException() {
        var field = new AltBn128Field();
        assertThrows(IllegalArgumentException.class, () -> field.fromLong(Long.MIN_VALUE));
    }

    @Test
    void createFieldFromLongIsEqualToZero() {
        var field = new AltBn128Field();
        assertEquals(field.zero(), field.fromLong(0));
        assertEquals(field.zero(), field.fromLong(0));
        assertEquals(field.fromLong(0), field.zero());
    }

    @Test
    void createFieldFromLongIsEqualToOne() {
        var field = new AltBn128Field();
        assertEquals(field.one(), field.fromLong(1));
        assertEquals(field.one(), field.fromLong(1));
        assertEquals(field.fromLong(1), field.one());
    }

    @Test
    void createFieldElementFromInvalidBytesThrowsException(final Random rng) {
        var field = new AltBn128Field();
        final byte[] value = new byte[field.elementSize() - 1];
        rng.nextBytes(value);
        assertThrows(IllegalArgumentException.class, () -> field.fromBytes(value));
        final byte[] value2 = new byte[field.elementSize() + 1];
        rng.nextBytes(value2);
        assertThrows(IllegalArgumentException.class, () -> field.fromBytes(value2));
    }

    @Test
    void equalityAndHashCode(final Random rng) {
        var field = new AltBn128Field();

        List<Long> values = rng.longs(10000, 0, Long.MAX_VALUE).boxed().toList();
        Set<Long> filtered = Set.copyOf(values);

        List<FieldElement> elements = values.stream().map(field::fromLong).toList();
        Set<FieldElement> elementsFiltered = new HashSet<>(elements);

        assertEquals(filtered.size(), elementsFiltered.size());

        for (int i = 0; i < values.size(); i++) {
            FieldElement element = field.fromLong(values.get(i));
            assertEquals(elements.get(i), element);
            assertEquals(elements.get(i).hashCode(), element.hashCode());
        }
    }
}
