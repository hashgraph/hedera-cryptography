/*
 * Copyright 2016-2022 Hedera Hashgraph, LLC
 *
 * This software is the confidential and proprietary information of
 * Hedera Hashgraph, LLC. ("Confidential Information"). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered into
 * with Hedera Hashgraph.
 *
 * HEDERA HASHGRAPH MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. HEDERA HASHGRAPH SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 */

package com.hedera.platform.bls;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("BLS12_381 Group Unit Tests")
class BLS12381GroupTests {
    BLS12381Field field;
    Random random;

    @BeforeEach
    public void init() {
        field = new BLS12381Field();
        random = RandomUtils.getRandomPrintSeed();
    }

    static Stream<Arguments> groups() {
        return Stream.of(
                Arguments.of(new BLS12381Group1()),
                Arguments.of(new BLS12381Group2()));
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("newElementFromSeed with unique seeds produces unique results")
    void newElementFromSeedUnique(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        assertTrue(randomElement1.isValid(), "randomElement1 should be valid");
        assertTrue(randomElement2.isValid(), "randomElement2 should be valid");
        assertNotEquals(randomElement1, randomElement2, "random elements shouldn't be equal");
        assertNotEquals(randomElement1, group.newOneElement(), "random element 1 shouldn't equal identity");
        assertNotEquals(randomElement2, group.newOneElement(), "random element 2 shouldn't equal identity");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("newElementFromSeed from same seed are equal")
    void newElementFromSeedDeterministic(final DistCryptGroup group) {
        final byte[] seed = RandomUtils.randomByteArray(random, group.getSeedSize());

        assertEquals(group.newElementFromSeed(seed), group.newElementFromSeed(seed),
                "elements from the same seed should be equal");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("newElementFromSeed with bad seed fails")
    void newElementFromBadSeed(final DistCryptGroup group) {
        final byte[] smallSeed = RandomUtils.randomByteArray(random, group.getSeedSize() - 1);
        final byte[] largeSeed = RandomUtils.randomByteArray(random, group.getSeedSize() + 1);

        assertThrows(IllegalArgumentException.class, () -> group.newElementFromSeed(smallSeed));
        assertThrows(IllegalArgumentException.class, () -> group.newElementFromSeed(largeSeed));
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("newElementFromBytes success")
    void newElementFromBytesSuccess(final DistCryptGroup group) {
        final byte[] seed = RandomUtils.randomByteArray(random, group.getSeedSize());

        final DistCryptGroupElement randomElementUncompressed = group.newElementFromSeed(seed);
        final DistCryptGroupElement randomElementCompressed = group.newElementFromSeed(seed).compress();

        final DistCryptGroupElement fromUncompressedBytes = group.newElementFromBytes(
                randomElementUncompressed.toBytes());
        final DistCryptGroupElement fromCompressedBytes = group.newElementFromBytes(
                randomElementCompressed.toBytes());

        assertNotEquals(null, fromUncompressedBytes, "valid element should be returned");
        assertNotEquals(null, fromCompressedBytes, "valid element should be returned");
        assertEquals(fromCompressedBytes, fromUncompressedBytes, "Elements from bytes should be equal");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("newElementFromBytes with wrong byte size")
    void newElementFromWrongBytesSize(final DistCryptGroup group) {
        final byte[] wrongSizeCompressedElementBytes = new byte[group.getCompressedSize() - 1];
        final byte[] wrongSizeUncompressedElementBytes = new byte[group.getUncompressedSize() - 1];

        Arrays.fill(wrongSizeCompressedElementBytes, (byte) 0xFF);
        Arrays.fill(wrongSizeUncompressedElementBytes, (byte) 0xFF);

        assertNull(group.newElementFromBytes(wrongSizeCompressedElementBytes),
                "Wrong byte size should return null");
        assertNull(group.newElementFromBytes(wrongSizeUncompressedElementBytes),
                "Wrong byte size should return null");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("newElementFromBytes returns null with invalid bytes")
    void newElementFromInvalidBytes(final DistCryptGroup group) {
        final byte[] invalidCompressedElementBytes = new byte[group.getCompressedSize()];
        final byte[] invalidUncompressedElementBytes = new byte[group.getUncompressedSize()];

        Arrays.fill(invalidCompressedElementBytes, (byte) 0xFF);
        Arrays.fill(invalidUncompressedElementBytes, (byte) 0xFF);

        assertNull(group.newElementFromBytes(invalidCompressedElementBytes),
                "null should be returned from invalid bytes");
        assertNull(group.newElementFromBytes(invalidUncompressedElementBytes),
                "null should be returned from invalid bytes");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("hashToGroup success")
    void hashToGroupSuccess(final DistCryptGroup group) {
        final byte[] dataToHash = {0x04, 0x08, 0x15, 0x16, 0x23, 0x42};
        DistCryptGroupElement groupElement = group.hashToGroup(dataToHash);

        assertTrue(groupElement.isValid(), "Element should be valid");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("newOneElement produces the same result every time")
    void newOneElementDeterministic(final DistCryptGroup group) {
        assertTrue(group.newOneElement().isValid(), "identity should be valid");
        assertEquals(group.newOneElement(), group.newOneElement(), "identity should equal identity");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("divide success")
    void divideSuccess(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement quotient = randomElement1.divide(randomElement2);

        assertTrue(quotient.isValid(), "quotient should be valid");
        assertNotEquals(quotient, randomElement1, "quotient shouldn't equal randomElement1");
        assertNotEquals(quotient, randomElement2, "quotient shouldn't equal randomElement2");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("divide compressed")
    void divideCompressed(final DistCryptGroup group) {
        final byte[] seed1 = RandomUtils.randomByteArray(random, group.getSeedSize());
        final byte[] seed2 = RandomUtils.randomByteArray(random, group.getSeedSize());

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(seed1);
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(seed2);

        final DistCryptGroupElement randomElement1Compressed = group.newElementFromSeed(seed1).compress();
        final DistCryptGroupElement randomElement2Compressed = group.newElementFromSeed(seed2).compress();

        final DistCryptGroupElement quotient = randomElement1.divide(randomElement2);
        final DistCryptGroupElement quotientCompressed = randomElement1Compressed.divide(randomElement2Compressed);
        final DistCryptGroupElement quotientMixed1 = randomElement1.divide(randomElement2Compressed);
        final DistCryptGroupElement quotientMixed2 = randomElement1Compressed.divide(randomElement2);

        assertTrue(quotient.isValid(), "quotient should be valid");
        assertTrue(quotientCompressed.isValid(), "quotientCompressed should be valid");
        assertTrue(quotientMixed1.isValid(), "quotientMixed1 should be valid");
        assertTrue(quotientMixed2.isValid(), "quotientMixed2 should be valid");

        assertEquals(quotient, quotientCompressed, "compression shouldn't affect result");
        assertEquals(quotient, quotientMixed1, "compression shouldn't affect result");
        assertEquals(quotient, quotientMixed2, "compression shouldn't affect result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("divide with null arguments throws error")
    void divideFailure(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        assertThrows(BLS12381Exception.class, () -> randomElement.divide(null),
                "Null argument should cause error");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("Dividing by identity doesn't change element")
    void divideByIdentity(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement quotient = randomElement.divide(group.newOneElement());

        assertTrue(quotient.isValid(), "quotient should be valid");
        assertEquals(randomElement, quotient, "dividing by identity shouldn't have an effect");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("divide produces the same result every time for identical inputs")
    void divideDeterministic(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement quotient1 = randomElement1.divide(randomElement2);
        final DistCryptGroupElement quotient2 = randomElement1.divide(randomElement2);

        assertTrue(quotient1.isValid(), "quotient1 should be valid");
        assertTrue(quotient2.isValid(), "quotient2 should be valid");
        assertEquals(quotient1, quotient2, "division with same inputs should produce same result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("multiply success")
    void multiplySuccess(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement product = randomElement1.multiply(randomElement2);

        assertTrue(product.isValid(), "product should be valid");
        assertNotEquals(randomElement1, product, "product shouldn't equal randomElement1");
        assertNotEquals(randomElement2, product, "product shouldn't equal randomElement2");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("multiply compressed")
    void multiplyCompressed(final DistCryptGroup group) {
        final byte[] seed1 = RandomUtils.randomByteArray(random, group.getSeedSize());
        final byte[] seed2 = RandomUtils.randomByteArray(random, group.getSeedSize());

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(seed1);
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(seed2);

        final DistCryptGroupElement randomElement1Compressed = group.newElementFromSeed(seed1).compress();
        final DistCryptGroupElement randomElement2Compressed = group.newElementFromSeed(seed2).compress();

        final DistCryptGroupElement product = randomElement1.multiply(randomElement2);
        final DistCryptGroupElement productCompressed = randomElement1Compressed.multiply(randomElement2Compressed);
        final DistCryptGroupElement productMixed1 = randomElement1.multiply(randomElement2Compressed);
        final DistCryptGroupElement productMixed2 = randomElement1Compressed.multiply(randomElement2);

        assertTrue(product.isValid(), "product should be valid");
        assertTrue(productCompressed.isValid(), "productCompressed should be valid");
        assertTrue(productMixed1.isValid(), "productMixed1 should be valid");
        assertTrue(productMixed2.isValid(), "productMixed2 should be valid");
        assertEquals(product, productCompressed, "compression shouldn't affect result");
        assertEquals(product, productMixed1, "compression shouldn't affect result");
        assertEquals(product, productMixed2, "compression shouldn't affect result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("multiply with null arguments throws error")
    void multiplyFailure(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        assertThrows(BLS12381Exception.class, () -> randomElement.multiply(null),
                "Null argument should cause error");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("Multiplying by identity doesn't change element")
    void multiplyByIdentity(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement product = randomElement.multiply(group.newOneElement());

        assertTrue(product.isValid(), "product should be valid");
        assertEquals(randomElement, product, "multiplying by identity shouldn't have an effect");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("multiply produces the same result every time for identical inputs")
    void multiplyDeterministic(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement product1 = randomElement1.multiply(randomElement2);
        final DistCryptGroupElement product2 = randomElement1.multiply(randomElement2);

        assertTrue(product1.isValid(), "product1 should be valid");
        assertTrue(product2.isValid(), "product2 should be valid");
        assertEquals(product1, product2, "multiplication with same inputs should produce same result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("multiply produces the same result when swapping operands")
    void multiplyCommutative(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement product1 = randomElement1.multiply(randomElement2);
        final DistCryptGroupElement product2 = randomElement2.multiply(randomElement1);

        assertTrue(product1.isValid(), "product1 should be valid");
        assertTrue(product2.isValid(), "product2 should be valid");
        assertEquals(product1, product2, "multiplication with swapped inputs should produce same result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("Multiply negates divide")
    void multiplyNegatesDivide(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement quotient = randomElement1.divide(randomElement2);
        final DistCryptGroupElement product = quotient.multiply(randomElement2);

        assertTrue(quotient.isValid(), "quotient should be valid");
        assertTrue(product.isValid(), "product should be valid");
        assertEquals(randomElement1, product, "multiply should negate divide");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("Divide negates multiply")
    void divideNegatesMultiply(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement product = randomElement1.multiply(randomElement2);
        final DistCryptGroupElement quotient = product.divide(randomElement2);

        assertTrue(product.isValid(), "product should be valid");
        assertTrue(quotient.isValid(), "quotient should be valid");
        assertEquals(randomElement1, quotient, "divide should negate multiply");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("batchMultiply success")
    void batchMultiplySuccess(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement identityElement = group.newOneElement();

        final Collection<DistCryptGroupElement> elements = Arrays.asList(
                randomElement1, randomElement2, identityElement);

        final DistCryptGroupElement batchProduct = group.batchMultiply(elements);
        final DistCryptGroupElement manualProduct = randomElement1.multiply(randomElement2).multiply(identityElement);

        assertTrue(batchProduct.isValid(), "batchProduct should be valid");
        for (final DistCryptGroupElement element : elements) {
            assertNotEquals(element, batchProduct, "product shouldn't equal random element");
        }

        assertEquals(manualProduct, batchProduct,
                "Batch multiplication and standard multiplication should yield same result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("batchMultiply compressed")
    void batchMultiplyCompressed(final DistCryptGroup group) {
        final byte[] seed1 = RandomUtils.randomByteArray(random, group.getSeedSize());
        final byte[] seed2 = RandomUtils.randomByteArray(random, group.getSeedSize());
        final byte[] seed3 = RandomUtils.randomByteArray(random, group.getSeedSize());

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(seed1);
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(seed2);
        final DistCryptGroupElement randomElement3 = group.newElementFromSeed(seed3);

        final DistCryptGroupElement randomElement1Compressed = group.newElementFromSeed(seed1).compress();
        final DistCryptGroupElement randomElement2Compressed = group.newElementFromSeed(seed2).compress();
        final DistCryptGroupElement randomElement3Compressed = group.newElementFromSeed(seed3).compress();

        final Collection<DistCryptGroupElement> elements = Arrays.asList(
                randomElement1, randomElement2, randomElement3);

        final Collection<DistCryptGroupElement> elementsCompressed = Arrays.asList(
                randomElement1Compressed, randomElement2Compressed, randomElement3Compressed);

        final Collection<DistCryptGroupElement> elementsMixed = Arrays.asList(
                randomElement1Compressed, randomElement2, randomElement3Compressed);

        final DistCryptGroupElement product = group.batchMultiply(elements);
        final DistCryptGroupElement productCompressed = group.batchMultiply(elementsCompressed);
        final DistCryptGroupElement productMixed = group.batchMultiply(elementsMixed);

        assertTrue(product.isValid(), "product should be valid");
        assertTrue(productCompressed.isValid(), "productCompressed should be valid");
        assertTrue(productMixed.isValid(), "productMixed should be valid");

        assertEquals(product, productCompressed, "compression shouldn't affect result");
        assertEquals(product, productMixed, "compression shouldn't affect result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("batchMultiply insufficient element count")
    void batchMultiplyInsufficientElements(final DistCryptGroup group) {
        // Batch multiplication requires at least 1 elements
        final Collection<DistCryptGroupElement> elements = new ArrayList<>();

        assertThrows(IllegalArgumentException.class, () -> group.batchMultiply(elements),
                "empty input collection should result in error");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("batchMultiply with invalid element")
    void batchMultiplyInvalidElement(final DistCryptGroup group) {
        final Collection<DistCryptGroupElement> elements = Arrays.asList(
                group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize())), null);

        assertThrows(BLS12381Exception.class, () -> group.batchMultiply(elements),
                "invalid element in batch should result in error");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("batchMultiply produces the same result every time for identical inputs")
    void batchMultiplyDeterministic(final DistCryptGroup group) {
        final Collection<DistCryptGroupElement> elements = Arrays.asList(
                group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize())),
                group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize())),
                group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize())));

        final DistCryptGroupElement product1 = group.batchMultiply(elements);
        final DistCryptGroupElement product2 = group.batchMultiply(elements);

        assertTrue(product1.isValid(), "product1 should be valid");
        assertTrue(product2.isValid(), "product2 should be valid");
        assertEquals(product1, product2, "multiplication with same inputs should produce same result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("batchMultiply produces the same result every time for identical inputs")
    void batchMultiplyCommutative(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement randomElement3 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final Collection<DistCryptGroupElement> elements1 = Arrays.asList(
                randomElement1, randomElement2, randomElement3);

        final Collection<DistCryptGroupElement> elements2 = Arrays.asList(
                randomElement2, randomElement3, randomElement1);

        final DistCryptGroupElement product1 = group.batchMultiply(elements1);
        final DistCryptGroupElement product2 = group.batchMultiply(elements2);

        assertTrue(product1.isValid(), "product1 should be valid");
        assertTrue(product2.isValid(), "product2 should be valid");
        assertEquals(product1, product2,
                "multiplication with same differently ordered batch inputs should produce same result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("power success")
    void powerSuccess(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement power =
                randomElement.power(field.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize())));

        assertTrue(power.isValid(), "power should be valid");
        assertNotEquals(randomElement, power, "power shouldn't equal randomElement");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("power compressed")
    void powerCompressed(final DistCryptGroup group) {
        final byte[] seed = RandomUtils.randomByteArray(random, group.getSeedSize());

        final DistCryptGroupElement randomElement = group.newElementFromSeed(seed);
        final DistCryptFieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement randomElementCompressed = group.newElementFromSeed(seed).compress();

        final DistCryptGroupElement power = randomElement.power(randomScalar);
        final DistCryptGroupElement powerCompressed = randomElementCompressed.power(randomScalar);

        assertTrue(power.isValid(), "power should be valid");
        assertTrue(powerCompressed.isValid(), "powerCompressed should be valid");
        assertEquals(power, powerCompressed, "compression shouldn't affect result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("Element to the power of 1")
    void powerOfOne(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement power = randomElement.power(field.newOneElement());

        assertTrue(power.isValid(), "power should be valid");
        assertEquals(randomElement, power, "element to the power of 1 should equal itself");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("Element to the power of 0")
    void powerOfZero(final DistCryptGroup group) {
        final DistCryptGroupElement power =
                group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize()))
                        .power(field.newZeroElement());

        assertTrue(power.isValid(), "power should be valid");
        assertEquals(group.newOneElement(), power, "element to the power of 0 should equal identity");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("power produces the same result every time for identical inputs")
    void powerDeterministic(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptFieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement power1 = randomElement.power(randomScalar);
        final DistCryptGroupElement power2 = randomElement.power(randomScalar);

        assertTrue(power1.isValid(), "power1 should be valid");
        assertTrue(power2.isValid(), "power2 should be valid");
        assertEquals(power1, power2, "power with same inputs should produce same result");
    }

    @Test()
    @DisplayName("group equality success")
    void groupEqualsSuccess() {
        DistCryptGroup group1A = new BLS12381Group1();
        DistCryptGroup group1B = new BLS12381Group1();

        DistCryptGroup group2A = new BLS12381Group2();
        DistCryptGroup group2B = new BLS12381Group2();

        assertEquals(group1A, group1B, "Group objects of the same class should equal each other");
        assertEquals(group2A, group2B, "Group objects of the same class should equal each other");
        assertNotEquals(group1A, group2A, "Group objects of different classes shouldn't be equal");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("group equality with null argument returns false")
    void groupEqualsInvalid(final DistCryptGroup group) {
        assertNotEquals(null, group, "One value being null should return false");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("a group equals itself")
    void groupEqualsSelf(final DistCryptGroup group) {
        assertEquals(group, group, "A group should equal itself");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("element equality with null argument returns false")
    void elementEqualsInvalid(final DistCryptGroup group) {
        assertNotEquals(null, group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize())),
                "One value being null should return false");
    }

    @Test()
    @DisplayName("element equality between different groups returns false")
    void elementEqualsWrongGroup() {
        DistCryptGroup group1 = new BLS12381Group1();
        DistCryptGroup group2 = new BLS12381Group2();
        DistCryptGroupElement group1Element = group1.newElementFromSeed(
                RandomUtils.randomByteArray(random, group1.getSeedSize()));
        DistCryptGroupElement group2Element = group2.newElementFromSeed(
                RandomUtils.randomByteArray(random, group2.getSeedSize()));

        assertNotEquals(group1Element, group2Element, "Elements of different groups should not equal one another");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("an element equals itself")
    void elementEqualsSelf(final DistCryptGroup group) {
        DistCryptGroupElement element = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        assertEquals(element, element, "an element should equal itself");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("uncompressed elements can be compared with compressed elements")
    void equalsCompressed(final DistCryptGroup group) {
        final byte[] seed = RandomUtils.randomByteArray(random, group.getSeedSize());
        final DistCryptGroupElement randomElement = group.newElementFromSeed(seed);
        final DistCryptGroupElement randomElementCompressed = group.newElementFromSeed(seed).compress();

        assertTrue(randomElementCompressed.isValid(), "randomElementCompressed should be valid");
        assertEquals(randomElement, randomElementCompressed, "comparison should work regardless of compression");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("compress success")
    void compressSuccess(final DistCryptGroup group) {
        final byte[] seed = RandomUtils.randomByteArray(random, group.getSeedSize());
        final DistCryptGroupElement randomElement = group.newElementFromSeed(seed);
        final DistCryptGroupElement randomElementCompressed = group.newElementFromSeed(seed).compress();

        assertEquals(group.getUncompressedSize(), randomElement.toBytes().length,
                "uncompressed element is of unexpected length");

        assertTrue(randomElementCompressed.isValid(), "randomElementCompressed should be valid");
        assertEquals(group.getCompressedSize(), randomElementCompressed.toBytes().length,
                "compressed element is of unexpected length");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("double compression")
    void doubleCompression(final DistCryptGroup group) {
        final DistCryptGroupElement doubleCompressedElement = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize())).compress().compress();

        assertTrue(doubleCompressedElement.isValid(), "doubleCompressedElement should be valid");
        assertEquals(group.getCompressedSize(), doubleCompressedElement.toBytes().length,
                "doubleCompressedElement is of unexpected length");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("copy success")
    void copySuccess(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));
        final DistCryptGroupElement copiedElement = randomElement.copy();

        assertEquals(randomElement, copiedElement, "A copied element should equal the original");
        assertNotSame(randomElement, copiedElement, "There should be 2 separate objects");
    }
}
