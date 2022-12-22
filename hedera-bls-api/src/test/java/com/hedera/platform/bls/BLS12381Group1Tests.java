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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("BLS12_381 Group 1 Unit Tests")
class BLS12381Group1Tests {
    BLS12381Group1 group;
    BLS12381Field field;

    @BeforeEach
    public void init() {
        group = new BLS12381Group1();
        field = new BLS12381Field();
    }

    @Test
    @DisplayName("newRandomG1 with unique seeds produces unique results")
    void newRandomElementUnique() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        assertNotEquals(null, randomElement1, "randomElement1 should be valid");
        assertNotEquals(null, randomElement2, "randomElement2 should be valid");
        assertNotEquals(randomElement1, randomElement2, "random elements shouldn't be equal");
        assertNotEquals(randomElement1, group.newOneElement(), "random element 1 shouldn't equal identity");
        assertNotEquals(randomElement2, group.newOneElement(), "random element 2 shouldn't equal identity");
    }

    @Test
    @DisplayName("getG1RandomElement from same seed are equal")
    void newRandomElementDeterministic() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final byte[] seed = RandomUtils.randomByteArray(random, 32);

        assertEquals(group.newElementFromSeed(seed), group.newElementFromSeed(seed),
                "elements from the same seed " + "should be equal");
    }

    @Test
    @DisplayName("newRandomG1 with bad seed fails")
    void newRandomG1BadSeed() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        assertNotEquals(0, BLS12381Group1Bindings.newRandomG1(RandomUtils.randomByteArray(random, 31), output));
        assertNotEquals(0, BLS12381Group1Bindings.newRandomG1(RandomUtils.randomByteArray(random, 33), output));
    }

    @Test
    @DisplayName("newG1Identity produces the same result every time")
    void newG1IdentityDeterministic() {
        assertNotEquals(null, group.newOneElement(), "identity should be valid");
        assertEquals(group.newOneElement(), group.newOneElement(), "identity should equal identity");
    }

    @Test
    @DisplayName("g1Divide success")
    void g1DivideSuccess() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement quotient = randomElement1.divide(randomElement2);

        assertNotEquals(null, quotient, "quotient should be valid");
        assertNotEquals(quotient, randomElement1, "quotient shouldn't equal randomElement1");
        assertNotEquals(quotient, randomElement2, "quotient shouldn't equal randomElement2");
    }

    @Test
    @DisplayName("g1Divide compressed")
    void g1DivideCompressed() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final byte[] seed1 = RandomUtils.randomByteArray(random, 32);
        final byte[] seed2 = RandomUtils.randomByteArray(random, 32);

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

    @Test
    @DisplayName("g1Divide with null arguments throws error")
    void g1DivideFailure() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        assertThrows(BLS12381Exception.class, () -> randomElement.divide(null), "Null argument should cause error");
    }

    @Test
    @DisplayName("Dividing by identity doesn't change element")
    void g1DivideByIdentity() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement quotient = randomElement.divide(group.newOneElement());

        assertNotEquals(null, quotient, "quotient should be valid");
        assertEquals(randomElement, quotient, "dividing by identity shouldn't have an effect");
    }

    @Test
    @DisplayName("g1Divide produces the same result every time for identical inputs")
    void g1DivideDeterministic() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement quotient1 = randomElement1.divide(randomElement2);
        final DistCryptGroupElement quotient2 = randomElement1.divide(randomElement2);

        assertNotEquals(null, quotient1, "quotient1 should be valid");
        assertNotEquals(null, quotient2, "quotient2 should be valid");
        assertEquals(quotient1, quotient2, "division with same inputs should produce same result");
    }

    @Test
    @DisplayName("g1Multiply success")
    void g1MultiplySuccess() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement product = randomElement1.multiply(randomElement2);

        assertNotEquals(null, product, "product should be valid");
        assertNotEquals(randomElement1, product, "product shouldn't equal randomElement1");
        assertNotEquals(randomElement2, product, "product shouldn't equal randomElement2");
    }

    @Test
    @DisplayName("g1Multiply compressed")
    void g1MultiplyCompressed() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final byte[] seed1 = RandomUtils.randomByteArray(random, 32);
        final byte[] seed2 = RandomUtils.randomByteArray(random, 32);

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

    @Test
    @DisplayName("g1Multiply with null arguments throws error")
    void g1MultiplyFailure() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        assertThrows(BLS12381Exception.class, () -> randomElement.multiply(null), "Null argument should cause error");
    }

    @Test
    @DisplayName("Multiplying by identity doesn't change element")
    void g1MultiplyByIdentity() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement product = randomElement.multiply(group.newOneElement());

        assertNotEquals(null, product, "product should be valid");
        assertEquals(randomElement, product, "multiplying by identity shouldn't have an effect");
    }

    @Test
    @DisplayName("g1Multiply produces the same result every time for identical inputs")
    void g1MultiplyDeterministic() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement product1 = randomElement1.multiply(randomElement2);
        final DistCryptGroupElement product2 = randomElement1.multiply(randomElement2);

        assertNotEquals(null, product1, "product1 should be valid");
        assertNotEquals(null, product2, "product2 should be valid");
        assertEquals(product1, product2, "multiplication with same inputs should produce same result");
    }

    @Test
    @DisplayName("g1Multiply produces the same result when swapping operands")
    void g1MultiplyCommutative() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement product1 = randomElement1.multiply(randomElement2);
        final DistCryptGroupElement product2 = randomElement2.multiply(randomElement1);

        assertNotEquals(null, product1, "product1 should be valid");
        assertNotEquals(null, product2, "product2 should be valid");
        assertEquals(product1, product2, "multiplication with swapped inputs should produce same result");
    }

    @Test
    @DisplayName("Multiply negates divide")
    void multiplyNegatesDivide() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement quotient = randomElement1.divide(randomElement2);
        final DistCryptGroupElement product = quotient.multiply(randomElement2);

        assertNotEquals(null, quotient, "quotient should be valid");
        assertNotEquals(null, product, "product should be valid");
        assertEquals(randomElement1, product, "multiply should negate divide");
    }

    @Test
    @DisplayName("Divide negates multiply")
    void divideNegatesMultiply() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement product = randomElement1.multiply(randomElement2);
        final DistCryptGroupElement quotient = product.divide(randomElement2);

        assertNotEquals(null, product, "product should be valid");
        assertNotEquals(null, quotient, "quotient should be valid");
        assertEquals(randomElement1, quotient, "divide should negate multiply");
    }

    @Test
    @DisplayName("g1BatchMultiply success")
    void g1BatchMultiplySuccess() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement3 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

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

    @Test
    @DisplayName("g1BatchMultiply compressed")
    void g1BatchMultiplyCompressed() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final byte[] seed1 = RandomUtils.randomByteArray(random, 32);
        final byte[] seed2 = RandomUtils.randomByteArray(random, 32);
        final byte[] seed3 = RandomUtils.randomByteArray(random, 32);

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

    @Test
    @DisplayName("g1BatchMultiply insufficient element count")
    void g1BatchMultiplyInsufficientElements() {
        final Random random = RandomUtils.getRandomPrintSeed();

        // Batch multiplication requires at least 2 elements
        final Collection<DistCryptGroupElement> elements = Collections.singletonList(
                group.newElementFromSeed(RandomUtils.randomByteArray(random, 32)));

        assertThrows(BLS12381Exception.class, () -> group.batchMultiply(elements),
                "not enough elements should result in error");
    }

    @Test
    @DisplayName("g1BatchMultiply with invalid element")
    void g1BatchMultiplyInvalidElement() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final Collection<DistCryptGroupElement> elements = Arrays.asList(
                group.newElementFromSeed(RandomUtils.randomByteArray(random, 32)), null);

        assertThrows(BLS12381Exception.class, () -> group.batchMultiply(elements),
                "invalid element in batch should result in error");
    }

    @Test
    @DisplayName("g1BatchMultiply produces the same result every time for identical inputs")
    void g1BatchMultiplyDeterministic() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final Collection<DistCryptGroupElement> elements = Arrays.asList(
                group.newElementFromSeed(RandomUtils.randomByteArray(random, 32)),
                group.newElementFromSeed(RandomUtils.randomByteArray(random, 32)),
                group.newElementFromSeed(RandomUtils.randomByteArray(random, 32)));

        final DistCryptGroupElement product1 = group.batchMultiply(elements);
        final DistCryptGroupElement product2 = group.batchMultiply(elements);

        assertNotEquals(null, product1, "product1 should be valid");
        assertNotEquals(null, product2, "product2 should be valid");
        assertEquals(product1, product2, "multiplication with same inputs should produce same result");
    }

    @Test
    @DisplayName("g1BatchMultiply produces the same result every time for identical inputs")
    void g1BatchMultiplyCommutative() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement1 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement2 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptGroupElement randomElement3 = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

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

    @Test
    @DisplayName("g1PowZn success")
    void g1PowZnSuccess() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement power =
                randomElement.power(field.newElementFromSeed(RandomUtils.randomByteArray(random, 32)));

        assertNotEquals(null, power, "power should be valid");
        assertNotEquals(randomElement, power, "power shouldn't equal randomElement");
    }

    @Test
    @DisplayName("g1PowZn compressed")
    void g1PowZnCompressed() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final byte[] seed = RandomUtils.randomByteArray(random, 32);

        final DistCryptGroupElement randomElement = group.newElementFromSeed(seed);
        final DistCryptFieldElement randomScalar = field.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement randomElementCompressed = group.newElementFromSeed(seed).compress();

        final DistCryptGroupElement power = randomElement.power(randomScalar);
        final DistCryptGroupElement powerCompressed = randomElementCompressed.power(randomScalar);

        assertNotEquals(null, power, "power should be valid");
        assertNotEquals(null, powerCompressed, "powerCompressed should be valid");
        assertEquals(power, powerCompressed, "compression shouldn't affect result");
    }

    @Test
    @DisplayName("Element to the power of 1")
    void g1PowZnOne() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement power = randomElement.power(field.newOneElement());

        assertNotEquals(null, power, "power should be valid");
        assertEquals(randomElement, power, "element to the power of 1 should equal itself");
    }

    @Test
    @DisplayName("Element to the power of 0")
    void g1PowZnZero() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement power =
                group.newElementFromSeed(RandomUtils.randomByteArray(random, 32)).power(field.newZeroElement());

        assertNotEquals(null, power, "power should be valid");
        assertEquals(group.newOneElement(), power, "element to the power of 0 should equal identity");
    }

    @Test
    @DisplayName("g1PowZn produces the same result every time for identical inputs")
    void g1PowZnDeterministic() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement randomElement = group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));
        final DistCryptFieldElement randomScalar = field.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        final DistCryptGroupElement power1 = randomElement.power(randomScalar);
        final DistCryptGroupElement power2 = randomElement.power(randomScalar);

        assertNotEquals(null, power1, "power1 should be valid");
        assertNotEquals(null, power2, "power2 should be valid");
        assertEquals(power1, power2, "power with same inputs should produce same result");
    }

    @Test
    @DisplayName("g1ElementEquals with null arguments returns false")
    void g1ElementEqualsInvalid() {
        final Random random = RandomUtils.getRandomPrintSeed();

        assertNotEquals(null, group.newElementFromSeed(RandomUtils.randomByteArray(random, 32)),
                "One value being null should return false");

    }

    @Test
    @DisplayName("uncompressed g1 elements can be compared with compressed elements")
    void g1EqualsCompressed() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final byte[] seed = RandomUtils.randomByteArray(random, 32);
        final DistCryptGroupElement randomElement = group.newElementFromSeed(seed);
        final DistCryptGroupElement randomElementCompressed = group.newElementFromSeed(seed).compress();

        assertNotEquals(null, randomElementCompressed, "randomElementCompressed should be valid");
        assertEquals(randomElement, randomElementCompressed, "comparison should work regardless of compression");
    }

    @Test
    @DisplayName("compress success")
    void compressSuccess() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final byte[] seed = RandomUtils.randomByteArray(random, 32);
        final DistCryptGroupElement randomElement = group.newElementFromSeed(seed);
        final DistCryptGroupElement randomElementCompressed = group.newElementFromSeed(seed).compress();

        assertEquals(96, randomElement.toBytes().length, "uncompressed element should be of length 96");

        assertNotEquals(null, randomElementCompressed, "compressedElement should be valid");
        assertEquals(48, randomElementCompressed.toBytes().length, "compressed element should be of length 48");
    }

    @Test
    @DisplayName("checkG1Validity valid")
    void checkG1ValidityValid() {
        final Random random = RandomUtils.getRandomPrintSeed();

        final DistCryptGroupElement validCompressedElement =
                group.newElementFromSeed(RandomUtils.randomByteArray(random, 32)).compress();

        final DistCryptGroupElement validUncompressedElement =
                group.newElementFromSeed(RandomUtils.randomByteArray(random, 32));

        assertTrue(BLS12381Group1Bindings.checkG1Validity((BLS12381Group1Element) validCompressedElement),
                "element should be valid");
        assertTrue(BLS12381Group1Bindings.checkG1Validity((BLS12381Group1Element) validUncompressedElement),
                "element should be valid");
    }

    @Test
    @DisplayName("checkG1Validity invalid")
    void checkG1ValidityInvalid() {
        final byte[] invalidCompressedElementBytes = new byte[48];
        final byte[] invalidUncompressedElementBytes = new byte[96];

        Arrays.fill(invalidCompressedElementBytes, (byte) 0xFF);
        Arrays.fill(invalidUncompressedElementBytes, (byte) 0xFF);

        final BLS12381Group1Element invalidCompressedElement =
                new BLS12381Group1Element(invalidCompressedElementBytes, new BLS12381Group1());

        final BLS12381Group1Element invalidUncompressedElement =
                new BLS12381Group1Element(invalidUncompressedElementBytes, new BLS12381Group1());

        assertFalse(BLS12381Group1Bindings.checkG1Validity(invalidCompressedElement), "element should be invalid");
        assertFalse(BLS12381Group1Bindings.checkG1Validity(invalidUncompressedElement), "element should be invalid");
    }
}
