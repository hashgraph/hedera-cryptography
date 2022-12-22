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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
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

        assertNotEquals(null, randomElement1, "randomElement1 should be valid");
        assertNotEquals(null, randomElement2, "randomElement2 should be valid");
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
    @DisplayName("newOneElement produces the same result every time")
    void newOneElementDeterministic(final DistCryptGroup group) {
        assertNotEquals(null, group.newOneElement(), "identity should be valid");
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

        assertNotEquals(null, quotient, "quotient should be valid");
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

        assertNotEquals(null, quotient, "quotient should be valid");
        assertNotEquals(null, quotientCompressed, "quotientCompressed should be valid");
        assertNotEquals(null, quotientMixed1, "quotientMixed1 should be valid");
        assertNotEquals(null, quotientMixed2, "quotientMixed2 should be valid");

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

        assertNotEquals(null, quotient, "quotient should be valid");
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

        assertNotEquals(null, quotient1, "quotient1 should be valid");
        assertNotEquals(null, quotient2, "quotient2 should be valid");
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

        assertNotEquals(null, product, "product should be valid");
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

        assertNotEquals(null, product, "product should be valid");
        assertNotEquals(null, productCompressed, "productCompressed should be valid");
        assertNotEquals(null, productMixed1, "productMixed1 should be valid");
        assertNotEquals(null, productMixed2, "productMixed2 should be valid");
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

        assertNotEquals(null, product, "product should be valid");
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

        assertNotEquals(null, product1, "product1 should be valid");
        assertNotEquals(null, product2, "product2 should be valid");
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

        assertNotEquals(null, product1, "product1 should be valid");
        assertNotEquals(null, product2, "product2 should be valid");
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

        assertNotEquals(null, quotient, "quotient should be valid");
        assertNotEquals(null, product, "product should be valid");
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

        assertNotEquals(null, product, "product should be valid");
        assertNotEquals(null, quotient, "quotient should be valid");
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
        final DistCryptGroupElement randomElement3 = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final Collection<DistCryptGroupElement> elements = Arrays.asList(
                randomElement1, randomElement2, randomElement3);

        final DistCryptGroupElement batchProduct = group.batchMultiply(elements);
        final DistCryptGroupElement manualProduct = randomElement1.multiply(randomElement2).multiply(randomElement3);

        assertNotEquals(null, batchProduct, "product should be valid");
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

        assertNotEquals(null, product, "product should be valid");
        assertNotEquals(null, productCompressed, "productCompressed should be valid");
        assertNotEquals(null, productMixed, "productMixed should be valid");

        assertEquals(product, productCompressed, "compression shouldn't affect result");
        assertEquals(product, productMixed, "compression shouldn't affect result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("batchMultiply insufficient element count")
    void batchMultiplyInsufficientElements(final DistCryptGroup group) {
        // Batch multiplication requires at least 2 elements
        final Collection<DistCryptGroupElement> elements = Collections.singletonList(
                group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize())));

        assertThrows(BLS12381Exception.class, () -> group.batchMultiply(elements),
                "not enough elements should result in error");
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

        assertNotEquals(null, product1, "product1 should be valid");
        assertNotEquals(null, product2, "product2 should be valid");
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

        assertNotEquals(null, product1, "product1 should be valid");
        assertNotEquals(null, product2, "product2 should be valid");
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

        assertNotEquals(null, power, "power should be valid");
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

        assertNotEquals(null, power, "power should be valid");
        assertNotEquals(null, powerCompressed, "powerCompressed should be valid");
        assertEquals(power, powerCompressed, "compression shouldn't affect result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("Element to the power of 1")
    void powerOfOne(final DistCryptGroup group) {
        final DistCryptGroupElement randomElement = group.newElementFromSeed(
                RandomUtils.randomByteArray(random, group.getSeedSize()));

        final DistCryptGroupElement power = randomElement.power(field.newOneElement());

        assertNotEquals(null, power, "power should be valid");
        assertEquals(randomElement, power, "element to the power of 1 should equal itself");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("Element to the power of 0")
    void powerOfZero(final DistCryptGroup group) {
        final DistCryptGroupElement power =
                group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize()))
                        .power(field.newZeroElement());

        assertNotEquals(null, power, "power should be valid");
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

        assertNotEquals(null, power1, "power1 should be valid");
        assertNotEquals(null, power2, "power2 should be valid");
        assertEquals(power1, power2, "power with same inputs should produce same result");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("equals with null arguments returns false")
    void equalsInvalid(final DistCryptGroup group) {
        assertNotEquals(null, group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize())),
                "One value being null should return false");

    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("uncompressed elements can be compared with compressed elements")
    void equalsCompressed(final DistCryptGroup group) {
        final byte[] seed = RandomUtils.randomByteArray(random, group.getSeedSize());
        final DistCryptGroupElement randomElement = group.newElementFromSeed(seed);
        final DistCryptGroupElement randomElementCompressed = group.newElementFromSeed(seed).compress();

        assertNotEquals(null, randomElementCompressed, "randomElementCompressed should be valid");
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

        assertNotEquals(null, randomElementCompressed, "compressedElement should be valid");
        assertEquals(group.getCompressedSize(), randomElementCompressed.toBytes().length,
                "compressed element is of unexpected length");
    }

    @ParameterizedTest()
    @MethodSource("groups")
    @DisplayName("checkValidity valid")
    void checkValidityValid(final DistCryptGroup group) {
        final DistCryptGroupElement validCompressedElement =
                group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize())).compress();

        final DistCryptGroupElement validUncompressedElement =
                group.newElementFromSeed(RandomUtils.randomByteArray(random, group.getSeedSize()));

        assertTrue(validCompressedElement.checkElementValidity(), "element should be valid");
        assertTrue(validUncompressedElement.checkElementValidity(), "element should be valid");
    }

    @Test()
    @DisplayName("group1 checkValidity invalid")
    void group1CheckValidityInvalid() {
        DistCryptGroup group = new BLS12381Group1();
        final byte[] invalidCompressedElementBytes = new byte[group.getCompressedSize()];
        final byte[] invalidUncompressedElementBytes = new byte[group.getUncompressedSize()];

        Arrays.fill(invalidCompressedElementBytes, (byte) 0xFF);
        Arrays.fill(invalidUncompressedElementBytes, (byte) 0xFF);

        final BLS12381Group1Element invalidCompressedElement =
                new BLS12381Group1Element(invalidCompressedElementBytes, new BLS12381Group1());

        final BLS12381Group1Element invalidUncompressedElement =
                new BLS12381Group1Element(invalidUncompressedElementBytes, new BLS12381Group1());

        assertFalse(BLS12381Group1Bindings.checkG1Validity(invalidCompressedElement), "element should be invalid");
        assertFalse(BLS12381Group1Bindings.checkG1Validity(invalidUncompressedElement), "element should be invalid");
    }

    @Test()
    @DisplayName("group2 checkValidity invalid")
    void group2CheckValidityInvalid() {
        BLS12381Group2 group = new BLS12381Group2();
        final byte[] invalidCompressedElementBytes = new byte[group.getCompressedSize()];
        final byte[] invalidUncompressedElementBytes = new byte[group.getUncompressedSize()];

        Arrays.fill(invalidCompressedElementBytes, (byte) 0xFF);
        Arrays.fill(invalidUncompressedElementBytes, (byte) 0xFF);

        final BLS12381Group2Element invalidCompressedElement =
                new BLS12381Group2Element(invalidCompressedElementBytes, group);

        final BLS12381Group2Element invalidUncompressedElement =
                new BLS12381Group2Element(invalidUncompressedElementBytes, group);

        assertFalse(BLS12381Group2Bindings.checkG2Validity(invalidCompressedElement), "element should be invalid");
        assertFalse(BLS12381Group2Bindings.checkG2Validity(invalidUncompressedElement), "element should be invalid");
    }
}
