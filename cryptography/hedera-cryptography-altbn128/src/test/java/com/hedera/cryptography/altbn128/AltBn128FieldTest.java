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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import org.junit.jupiter.api.Test;

class AltBn128FieldTest {

    @Test
    void constructionSucceeds() {
        assertDoesNotThrow(AltBn128Field::new);
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
        assertFalse(field.zero().equals(field.one()));
        assertFalse(field.one().equals(field.zero()));
    }

    @Test
    void createRandomFieldElementIsNotNull() {
        var field = new AltBn128Field();
        Random rng = new SecureRandom();
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
    void createFieldFromLongIsNotNull() {
        var field = new AltBn128Field();
        Random rng = new SecureRandom();
        var value = rng.nextLong();
        assertNotNull(field.fromLong(value));
    }

    @Test
    void createFieldElementFromNegativeLongIsNotNull() {
        var field = new AltBn128Field();
        assertNotNull(field.fromLong(-1));
    }

    @Test
    void createFieldElementFromNegativeLongMaxValue() {
        var field = new AltBn128Field();
        assertNotNull(field.fromLong(Long.MAX_VALUE));
    }

    @Test
    void createFieldElementFromNegativeLongMinValue() {
        var field = new AltBn128Field();
        assertNotNull(field.fromLong(Long.MIN_VALUE));
    }

    @Test
    void createFieldFromLongIsEqualToZero() {
        var field = new AltBn128Field();
        assertEquals(field.zero(), field.fromLong(0));
        assertTrue(field.zero().equals(field.fromLong(0)));
        assertTrue(field.fromLong(0).equals(field.zero()));
    }

    @Test
    void createFieldFromLongIsEqualToOne() {
        var field = new AltBn128Field();
        assertEquals(field.one(), field.fromLong(1));
        assertTrue(field.one().equals(field.fromLong(1)));
        assertTrue(field.fromLong(1).equals(field.one()));
    }

    @Test
    void createFieldElementFromInvalidBytesThrowsException() {
        var field = new AltBn128Field();
        Random rng = new SecureRandom();
        final byte[] value = new byte[field.elementSize() - 1];
        rng.nextBytes(value);
        assertThrows(IllegalArgumentException.class, () -> field.fromBytes(value));
        final byte[] value2 = new byte[field.elementSize() + 1];
        rng.nextBytes(value2);
        assertThrows(IllegalArgumentException.class, () -> field.fromBytes(value2));
    }

    @Test
    void fieldElementToBytesIsNotNull() {
        var field = new AltBn128Field();
        assertNotNull(field.one().toBytes());
    }

    @Test
    void fieldElementToBytesAndInverseIsEquals() {
        var field = new AltBn128Field();
        byte[] representation = field.one().toBytes();
        assertEquals(field.fromBytes(representation), field.one());
        assertTrue(field.one().equals(field.fromBytes(representation)));
        assertTrue(field.fromBytes(representation).equals(field.one()));
    }

    @Test
    void fieldElementToBigIntegerIsNotNull() {
        var field = new AltBn128Field();
        assertNotNull(field.one().toBigInteger());
    }

    @Test
    void fieldElementToBigInteger() {
        var field = new AltBn128Field();
        assertEquals(BigInteger.ONE, field.one().toBigInteger());
        assertEquals(BigInteger.ZERO, field.zero().toBigInteger());
        assertEquals(BigInteger.TEN, field.fromLong(10L).toBigInteger());
    }
}
