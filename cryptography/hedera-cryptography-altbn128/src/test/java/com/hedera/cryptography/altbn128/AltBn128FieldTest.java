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
import static org.mockito.Mockito.mock;

import com.hedera.cryptography.pairings.api.Group;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;
import org.junit.jupiter.api.Test;

class AltBn128FieldTest {

    @Test
    void constructionSucceeds() {
        assertDoesNotThrow(() -> new AltBn128Field(mock(Group.class)));
    }

    @Test
    void createFieldElementOneIsNotNull() {
        var field = new AltBn128Field(mock(Group.class));
        assertNotNull(field.one());
    }

    @Test
    void createFieldElementZeroIsNotNull() {
        var field = new AltBn128Field(mock(Group.class));
        assertNotNull(field.zero());
    }

    @Test
    void zeroNotEqualsOne() {
        var field = new AltBn128Field(mock(Group.class));
        assertNotEquals(field.zero(), field.one());
        assertFalse(field.zero().equals(field.one()));
        assertFalse(field.one().equals(field.zero()));
    }

    @Test
    void createRandomFieldElementIsNotNull() {
        var field = new AltBn128Field(mock(Group.class));
        Random rng = new SecureRandom();
        final byte[] seed = new byte[field.getSeedSize()];
        rng.nextBytes(seed);
        assertNotNull(field.randomElement(seed));
    }

    @Test
    void createRandomFieldWithSmallerSeedThrowsException() {
        var field = new AltBn128Field(mock(Group.class));
        final byte[] smallerSeed = new byte[field.getSeedSize() - 1];
        final byte[] largerSeed = new byte[field.getSeedSize() + 1];
        assertThrows(IllegalArgumentException.class, () -> field.randomElement(smallerSeed));
        assertThrows(IllegalArgumentException.class, () -> field.randomElement(largerSeed));
    }

    @Test
    void createFieldElementFromLongIsNotNull() {
        var field = new AltBn128Field(mock(Group.class));
        Random rng = new SecureRandom();
        var value = rng.nextLong();
        assertNotNull(field.elementFromLong(value));
    }

    @Test
    void createFieldElementFromNegativeLongIsNotNull() {
        var field = new AltBn128Field(mock(Group.class));
        assertNotNull(field.elementFromLong(-1));
    }

    @Test
    void createFieldElementFromNegativeLongMaxValue() {
        var field = new AltBn128Field(mock(Group.class));
        assertNotNull(field.elementFromLong(Long.MAX_VALUE));
    }

    @Test
    void createFieldElementFromNegativeLongMinValue() {
        var field = new AltBn128Field(mock(Group.class));
        assertNotNull(field.elementFromLong(Long.MIN_VALUE));
    }

    @Test
    void createFieldElementFromLongIsEqualToZero() {
        var field = new AltBn128Field(mock(Group.class));
        assertEquals(field.zero(), field.elementFromLong(0));
        assertTrue(field.zero().equals(field.elementFromLong(0)));
        assertTrue(field.elementFromLong(0).equals(field.zero()));
    }

    @Test
    void createFieldElementFromLongIsEqualToOne() {
        var field = new AltBn128Field(mock(Group.class));
        assertEquals(field.one(), field.elementFromLong(1));
        assertTrue(field.one().equals(field.elementFromLong(1)));
        assertTrue(field.elementFromLong(1).equals(field.one()));
    }

    @Test
    void createFieldElementFromInvalidBytesThrowsException() {
        var field = new AltBn128Field(mock(Group.class));
        Random rng = new SecureRandom();
        final byte[] value = new byte[field.getElementSize() - 1];
        rng.nextBytes(value);
        assertThrows(IllegalArgumentException.class, () -> field.elementFromBytes(value));
        final byte[] value2 = new byte[field.getElementSize() + 1];
        rng.nextBytes(value2);
        assertThrows(IllegalArgumentException.class, () -> field.elementFromBytes(value2));
    }

    @Test
    void fieldElementToBytesIsNotNull() {
        var field = new AltBn128Field(mock(Group.class));
        assertNotNull(field.one().toBytes());
    }

    @Test
    void fieldElementToBytesAndInverseIsEquals() {
        var field = new AltBn128Field(mock(Group.class));
        byte[] representation = field.one().toBytes();
        assertEquals(field.elementFromBytes(representation), field.one());
        assertTrue(field.one().equals(field.elementFromBytes(representation)));
        assertTrue(field.elementFromBytes(representation).equals(field.one()));
    }

    @Test
    void fieldElementToBigIntegerIsNotNull() {
        var field = new AltBn128Field(mock(Group.class));
        assertNotNull(field.one().toBigInteger());
    }

    @Test
    void fieldElementToBigIntegerIsLittleEndianOne() {
        var field = new AltBn128Field(mock(Group.class));

        ByteBuffer bb = ByteBuffer.allocate(field.getSeedSize());
        bb.put(0, (byte) 1);
        BigInteger littleEndianOne = new BigInteger(bb.array());

        assertEquals(littleEndianOne, field.one().toBigInteger());
    }
}
