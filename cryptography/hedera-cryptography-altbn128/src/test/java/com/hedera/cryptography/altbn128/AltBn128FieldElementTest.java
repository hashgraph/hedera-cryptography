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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.utils.ByteArrayUtils;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AltBn128FieldElementTest {

    public static final BigInteger R =
            new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    public static final int SIZE = 32;

    @Test
    void fieldElementEquality() {
        final AltBn128Field mock = mock(AltBn128Field.class);
        final byte[] thizz = new byte[32];
        final byte[] anotherOne = thizz.clone();
        anotherOne[0] = 1;
        final byte[] anotherTwo = thizz.clone();
        anotherTwo[0] = 2;

        var value = new AltBn128FieldElement(thizz, mock);
        var value2 = new AltBn128FieldElement(anotherOne, mock(AltBn128Field.class));
        var value3 = new AltBn128FieldElement(anotherTwo, mock);
        var value4 = new AltBn128FieldElement(thizz, mock(AltBn128Field.class));
        var value5 = new AltBn128FieldElement(new byte[30], mock);

        assertEquals(value, value);
        assertTrue(value.equals(value));
        assertNotEquals(value, value2);
        assertFalse(value.equals(value2));
        assertFalse(value2.equals(value));
        assertNotEquals(value, value3);
        assertFalse(value.equals(value3));
        assertFalse(value3.equals(value));
        assertEquals(value, value4);
        assertTrue(value.equals(value4));
        assertTrue(value4.equals(value));
        assertNotEquals(value, mock(FieldElement.class));
        assertNotEquals(value, value5);
        assertFalse(value.equals(value5));
        assertFalse(value5.equals(value));
    }

    @Test
    void fieldElementHashCode() {
        final AltBn128Field mock = mock(AltBn128Field.class);
        final byte[] thizz = new byte[32];

        Set<AltBn128FieldElement> set = new HashSet<>();
        set.add(new AltBn128FieldElement(thizz, mock));
        set.add(new AltBn128FieldElement(thizz.clone(), mock));
        set.add(new AltBn128FieldElement(new byte[32], mock));
        set.add(new AltBn128FieldElement(new byte[32], mock));

        assertEquals(1, set.size());
        set.add(new AltBn128FieldElement(new byte[33], mock));
        assertEquals(2, set.size());
        set.add(new AltBn128FieldElement(new byte[32], mock(AltBn128Field.class)));
        assertEquals(2, set.size());
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
        final BigInteger rMinusOne = R.subtract(BigInteger.ONE);
        assertArrayEquals(
                ByteArrayUtils.toLittleEndianBytes(rMinusOne, SIZE),
                field.fromBytes(ByteArrayUtils.toLittleEndianBytes(rMinusOne, SIZE))
                        .toBytes());
        assertEquals(
                BigInteger.ZERO,
                field.fromBytes(ByteArrayUtils.toLittleEndianBytes(R, SIZE)).toBigInteger());
        final BigInteger rPlusOne = R.add(BigInteger.ONE);
        assertEquals(
                BigInteger.ONE,
                field.fromBytes(ByteArrayUtils.toLittleEndianBytes(rPlusOne, SIZE))
                        .toBigInteger());
    }

    @Test
    void fieldElementAddition() {
        var field = new AltBn128Field();
        assertEquals(field.zero(), field.zero().add(field.zero()));
        assertEquals(field.one(), field.one().add(field.zero()));
        assertEquals(field.one(), field.zero().add(field.one()));
        assertEquals(field.one(), field.fromBigInteger(R).add(field.one()));

        SecureRandom rng = new SecureRandom();
        var a = field.random(rng);
        var b = field.random(rng);
        var c = field.random(rng);
        assertEquals(a.add(b.add(c)), b.add(a.add(c)));
        assertEquals(c.add(b.add(a)), c.add(a.add(b)));
    }

    @Test
    void fieldElementSubtraction() {
        var field = new AltBn128Field();
        assertEquals(field.one(), field.one().subtract(field.zero()));
        assertEquals(
                field.fromBigInteger(R.subtract(BigInteger.ONE)), field.zero().subtract(field.one()));
        assertEquals(field.zero(), field.one().subtract(field.one()));

        SecureRandom rng = new SecureRandom();
        var a = field.random(rng);
        var b = field.random(rng);
        var c = field.random(rng);
        assertEquals(a.add(b.add(c)), b.add(a.add(c)));
        assertEquals(c.add(b.add(a)), c.add(a.add(b)));
    }

    @Test
    void fieldElementMultiplication() {
        var field = new AltBn128Field();
        assertEquals(field.zero(), field.zero().multiply(field.zero()));
        assertEquals(field.zero(), field.one().multiply(field.zero()));
        assertEquals(field.one(), field.one().multiply(field.one()));
        assertEquals(field.zero(), field.fromBigInteger(R).multiply(field.one()));
        assertEquals(field.one(), field.fromBigInteger(R.add(BigInteger.ONE)).multiply(field.one()));

        SecureRandom rng = new SecureRandom();
        var a = field.random(rng);
        var b = field.random(rng);
        var c = field.random(rng);
        assertEquals(a.multiply(b.add(c)), a.multiply(b).add(a.multiply(c)));
        assertEquals(a.multiply(b.subtract(c)), a.multiply(b).subtract(a.multiply(c)));
    }

    @Test
    void fieldElementInverse() {
        var field = new AltBn128Field();
        SecureRandom rng = new SecureRandom();
        var a = field.random(rng);
        assertEquals(field.one(), a.multiply(a.inverse()));
        assertThrows(IllegalArgumentException.class, () -> field.zero().inverse());
    }

    @Test
    void fieldElementPow() {
        var field = new AltBn128Field();
        SecureRandom rng = new SecureRandom();
        var a = field.random(rng);
        assertEquals(field.one(), a.power(0));
        assertEquals(a, a.power(1));
        assertThrows(IllegalArgumentException.class, () -> a.power(-1));
    }

    @Test
    void fieldElementInvalidOperations() {
        var field = new AltBn128Field();
        assertThrows(IllegalArgumentException.class, () -> field.zero().add(mock(FieldElement.class)));
        assertThrows(IllegalArgumentException.class, () -> field.zero().subtract(mock(FieldElement.class)));
    }

    @Test
    void fieldGetGroup() {
        var field = new AltBn128Field();
        assertEquals(field, field.zero().field());
    }
}
