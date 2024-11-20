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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.ByteArrayUtils;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import com.hedera.cryptography.utils.test.fixtures.stream.StreamUtils;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@WithRng
class AltBn128GroupElementTest {

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void zeroPlusZeroIsZero(AltBN128CurveGroup gr) {
        var field = new AltBn128Field();
        var group = new AltBn128Group(gr, field);
        assertEquals(group.zero(), group.zero().add(group.zero()));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void generatorTimesTwoEqualsGeneratorPlusGenerator(AltBN128CurveGroup gr) {
        var field = new AltBn128Field();
        var group = new AltBn128Group(gr, field);
        assertEquals(
                group.generator().multiply(field.fromLong(2)), group.generator().add(group.generator()));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void generatorBatchAddedFourTimesEqualsGeneratorTimes4(AltBN128CurveGroup gr) {
        var field = new AltBn128Field();
        var group = new AltBn128Group(gr, field);
        assertEquals(
                group.add(List.of(group.generator(), group.generator(), group.generator(), group.generator())),
                group.generator().multiply(field.fromLong(4)));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void generatorBatchAddedFourTimesAndZerosEqualsGeneratorTimes4(AltBN128CurveGroup gr) {
        var field = new AltBn128Field();
        var group = new AltBn128Group(gr, field);
        assertEquals(
                group.add(List.of(
                        group.zero(),
                        group.generator(),
                        group.generator(),
                        group.generator(),
                        group.generator(),
                        group.zero())),
                group.generator().multiply(field.fromLong(4)));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void generatorPlusZeroIsGenerator(AltBN128CurveGroup gr) {
        var field = new AltBn128Field();
        var group = new AltBn128Group(gr, field);
        assertEquals(group.generator(), group.generator().add(group.zero()));
        assertEquals(group.generator(), group.zero().add(group.generator()));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void toBytesAndPointAgain(AltBN128CurveGroup gr) {
        var field = new AltBn128Field();
        var group = new AltBn128Group(gr, field);
        assertEquals(group.zero(), group.fromBytes(group.zero().toBytes()));
        assertEquals(group.generator(), group.fromBytes(group.generator().toBytes()));
    }

    @Test
    void g2GeneratorIsWellKnown() {
        var field = new AltBn128Field();
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP2, field);
        assertEquals(
                ByteArrayUtils.toBigIntegers(group.generator().toBytes(), 32),
                List.of(
                        new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
                        new BigInteger("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
                        new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                        new BigInteger(
                                "4082367875863433681332203403145435568316851327593401208105741076214120093531")));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void zeroIsZero(AltBN128CurveGroup g) {
        var group = new AltBn128Group(g);

        assertEquals(group.zero(), group.fromBytes(group.zero().toBytes()) );
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void pointNotInCurve(AltBN128CurveGroup g) {
        var group = new AltBn128Group(g);
        var nonZero = new byte[group.elementSize()];
        Arrays.fill(nonZero, (byte)0);
        assertThrows(IllegalArgumentException.class,()-> group.fromBytes(nonZero) );
    }

    @Test
    void g1GeneratorIsWellKnown() {
        var field = new AltBn128Field();
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP1, field);

        assertEquals(
                ByteArrayUtils.toBigIntegers(group.generator().toBytes(), 32),
                List.of(new BigInteger("1"), new BigInteger("2")));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void fromInvalidPoint(AltBN128CurveGroup gr) {
        var field = new AltBn128Field();
        var group = new AltBn128Group(gr, field);
        assertThrows(
                IllegalArgumentException.class,
                () -> group.fromBytes(ByteArrayUtils.toLittleEndianBytes(
                        group.elementSize(), BigInteger.ONE, new BigInteger("10"), BigInteger.ONE, BigInteger.ONE)));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void fromInvalidPointOperation(AltBN128CurveGroup gr) {
        //We've chosen not to do this to gain some performance
        var group = new AltBn128Group(gr);
        var field = new AltBn128Field();
        var something = ByteArrayUtils.toLittleEndianBytes(
                group.elementSize(), BigInteger.ONE, new BigInteger("10"), BigInteger.ONE, BigInteger.ONE);
        var invalid = new AltBn128GroupElement(group, something );
        assertDoesNotThrow( ()->group.generator().add(invalid));
        assertDoesNotThrow( ()->invalid.multiply(field.one()));
    }


    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void batchMultiply(AltBN128CurveGroup gr, Random random) {
        var field = new AltBn128Field();
        var group = new AltBn128Group(gr, field);
        List<FieldElement> scalars =
                IntStream.range(0, 100).boxed().map(field::fromLong).toList();
        List<GroupElement> results =
                IntStream.range(0, 100).boxed().map(i -> group.random(random)).toList();
        var result = group.mbc(results, scalars);

        var expected = StreamUtils.zipStream(scalars, results)
                .map(e -> e.getValue().multiply(e.getKey()))
                .reduce(group.zero(), GroupElement::add);

        assertEquals(expected, result);
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void groupElementAdditionAssociativity(final AltBN128CurveGroup gr, final Random random) {
        var group = new AltBn128Group(gr);
        var G1 = group.generator();
        var G2 = group.generator().multiply(new AltBn128Field().fromLong(random.nextLong(Long.MAX_VALUE)));
        var G3 = group.generator().multiply(new AltBn128Field().fromLong(random.nextLong(Long.MAX_VALUE)));
        assertEquals(G1.add(G2).add(G3), G1.add(G2.add(G3)));
    }

    @Test
    void fieldElementAdditionCommutativity(final Random rng) {
        var field = new AltBn128Field();
        var a = field.random(rng);
        var b = field.random(rng);
        assertEquals(a.add(b), b.add(a));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testAdditiveIdentity(AltBN128CurveGroup gr) {
        var group = new AltBn128Group(gr);
        var element = group.generator();
        var identity = group.zero();

        // Check G + 0 = G
        assertEquals(element, element.add(identity));
        assertEquals(element, identity.add(element));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testScalarMultiplicationWithOneAndZero(AltBN128CurveGroup gr) {
        var group = new AltBn128Group(gr);
        var field = new AltBn128Field();
        var element = group.generator();

        // Check that 1 * G = G
        assertEquals(element, element.multiply(field.fromLong(1)));

        // Check that 0 * G = 0
        assertEquals(group.zero(), element.multiply(field.fromLong(0)));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testAdditionCommutativity(AltBN128CurveGroup gr) {
        var group = new AltBn128Group(gr);
        var G1 = group.generator();
        var G2 = group.generator().multiply(new AltBn128Field().fromLong(2));

        // Check G1 + G2 = G2 + G1
        assertEquals(G1.add(G2), G2.add(G1));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testAdditionAssociativity(final AltBN128CurveGroup gr, final Random random) {
        var group = new AltBn128Group(gr);
        var G1 = group.generator();
        var G2 = group.generator().multiply(new AltBn128Field().fromLong(random.nextLong(Long.MAX_VALUE)));
        var G3 = group.generator().multiply(new AltBn128Field().fromLong(random.nextLong(Long.MAX_VALUE)));

        // Check (G1 + G2) + G3 = G1 + (G2 + G3)
        assertEquals(G1.add(G2).add(G3), G1.add(G2.add(G3)));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testPointDoubling(AltBN128CurveGroup gr) {
        var group = new AltBn128Group(gr);
        var field = new AltBn128Field();
        var G = group.generator();

        // Check that 2 * G = G + G
        assertEquals(G.multiply(field.fromLong(2)), G.add(G));
    }

    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testRandomPointsWithinBounds(final AltBN128CurveGroup gr, final Random rng) {
        final var group = new AltBn128Group(gr);
        final byte[] seed = new byte[group.seedSize()];
        rng.nextBytes(seed);

        final var randomPoint = group.random(seed);

        // Ensure the point is not null
        assertNotNull(randomPoint, "Random point should not be null");
    }

    @Test
    void equality() {
        var field = new AltBn128Field();

        var group = new AltBn128Group(AltBN128CurveGroup.GROUP1, field);
        var group2 = new AltBn128Group(AltBN128CurveGroup.GROUP2, field);
        assertEquals(group.zero(), group.zero());
        assertNotEquals(group.zero(), new Object());
        assertNotEquals(group.zero(), group.generator());
        assertNotEquals(group.generator(), group.zero());
        assertNotEquals(group.generator(), null);
        assertNotEquals(group.generator(), mock(GroupElement.class));
        assertNotEquals(mock(GroupElement.class), group.generator());
        assertNotEquals(group.zero(), group2.zero());
        assertNotEquals(group.generator(), group2.generator());
    }

    @Test
    void testHashCode() {
        var field = new AltBn128Field();
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP1, field);
        var group2 = new AltBn128Group(AltBN128CurveGroup.GROUP2, field);
        var set = new HashSet<GroupElement>();
        set.add(group.zero());
        set.add(group.zero());
        assertEquals(1, set.size());
        set.add(group2.zero());
        assertEquals(2, set.size());
    }

    @Test
    void itDoesNotAcceptOperationsBetweenDifferentElements() {
        var field = new AltBn128Field();
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP1, field);
        var group2 = new AltBn128Group(AltBN128CurveGroup.GROUP2, field);
        // Checks Disabled for now
        // assertTrue(group2.zero().isSameGroup(group2.generator()));
        // assertTrue(group.zero().isSameGroup(group.generator()));
        // assertEquals(group, group2.getOppositeGroup());
        // assertEquals(group2, group.getOppositeGroup());

        assertThrows(IllegalArgumentException.class, () -> group.zero().add(group2.zero()));
        assertThrows(IllegalArgumentException.class, () -> group2.zero().add(group.zero()));
        assertThrows(IllegalArgumentException.class, () -> group2.zero().multiply(mock(FieldElement.class)));
        assertThrows(IllegalArgumentException.class, () -> group.zero().multiply(mock(FieldElement.class)));
    }

    @Test
    void testSizes() {
        var field = new AltBn128Field();
        var group = new AltBn128Group(AltBN128CurveGroup.GROUP1, field);
        var group2 = new AltBn128Group(AltBN128CurveGroup.GROUP2, field);
        assertEquals(group.elementSize(), group.zero().size());
        assertEquals(group2.elementSize(), group2.zero().size());
    }

    @SuppressWarnings("deprecation")
    @ParameterizedTest
    @EnumSource(AltBN128CurveGroup.class)
    void testCopy(AltBN128CurveGroup gr, Random rng) {
        var field = new AltBn128Field();
        var group = new AltBn128Group(gr, field);
        final byte[] seed = new byte[group.seedSize()];
        rng.nextBytes(seed);
        var random = group.random(seed);

        assertEquals(random, random.copy());
        assertNotSame(random, random.copy());
    }
}
