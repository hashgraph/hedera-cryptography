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

import com.hedera.cryptography.altbn128.common.BigIntegerUtils;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class AltBn128GroupElementTest {

    @Test
    void zeroPlusZeroIsZero() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        assertEquals(group.zero(), group.zero().add(group.zero()));
    }

    @Test
    void generatorTimesTwoEqualsGeneratorPlusGenerator() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        var field = new AltBn128Field();
        assertEquals(
                group.generator().multiply(field.fromLong(2)), group.generator().add(group.generator()));
    }

    @Test
    void generatorBatchAddedFourTimesEqualsGeneratorTimes4() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        var field = new AltBn128Field();
        assertEquals(
                group.batchAdd(List.of(group.generator(), group.generator(), group.generator(), group.generator())),
                group.generator().multiply(field.fromLong(4)));
    }

    @Test
    void generatorBatchAddedFourTimesAndZerosEqualsGeneratorTimes4() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        var field = new AltBn128Field();
        assertEquals(
                group.batchAdd(List.of(
                        group.zero(),
                        group.generator(),
                        group.generator(),
                        group.generator(),
                        group.generator(),
                        group.zero())),
                group.generator().multiply(field.fromLong(4)));
    }

    @Test
    void generatorPlusZeroIsGenerator() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        assertEquals(group.generator(), group.generator().add(group.zero()));
        assertEquals(group.generator(), group.zero().add(group.generator()));
    }

    @Test
    void toBytesAndPointAgain() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        assertEquals(group.zero(), group.fromBytes(group.zero().toBytes()));
        assertEquals(group.generator(), group.fromBytes(group.generator().toBytes()));
    }

    @Test
    void g2GeneratorIsWellKnown() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        assertEquals(
                BigIntegerUtils.toBigIntegers(group.generator().toBytes(), 32),
                List.of(
                        new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
                                new BigInteger(
                                        "11559732032986387107991004021392285783925812861821192530917403151452391805634"),
                        new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                                new BigInteger(
                                        "4082367875863433681332203403145435568316851327593401208105741076214120093531")));
    }

    @Test
    void fromInvalidPoint() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        assertThrows(
                IllegalArgumentException.class,
                () -> group.fromBytes(BigIntegerUtils.toLittleEndianBytes(
                        128, BigInteger.ONE, new BigInteger("10"), BigInteger.ONE, BigInteger.ONE)));
    }

    @Test
    void batchMultiply() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        var field = new AltBn128Field();
        List<FieldElement> scalars =
                IntStream.range(0, 100).boxed().map(field::fromLong).toList();
        List<GroupElement> results = new ArrayList<>();
        assertDoesNotThrow(() -> results.addAll(group.batchMultiply(scalars)));

        IntStream.range(0, results.size()).forEach(index -> {
            assertEquals(
                    group.generator().multiply(field.fromLong(index)),
                    results.get(index),
                    "result " + index + " is not correct");
        });
    }

    @Test
    void equality() {
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        var group2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        assertEquals(group.zero(), group.zero());
        final GroupElement zero = group.zero();
        assertTrue(zero.equals(zero));
        assertNotEquals(group.zero(), group.generator());
        assertNotEquals(group.generator(), group.zero());
        assertNotEquals(group.generator(), null);
        assertNotEquals(group.generator(), mock(GroupElement.class));
        assertNotEquals(mock(GroupElement.class), group.generator());
        assertNotEquals(group.zero(), group2.zero());
        assertNotEquals(group.generator(), group2.generator());
    }
}
