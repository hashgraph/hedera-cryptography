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

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("BLS12_381 Scalar Unit Tests")
class BLS12381ScalarTests {
    BLS12381Field field;
    Random random;

    @BeforeEach
    public void init() {
        field = new BLS12381Field();
        random = RandomUtils.getRandomPrintSeed();
    }

    @Test
    @DisplayName("newRandomScalar with unique seeds produces unique results")
    void newRandomScalarUnique() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        assertTrue(randomScalar1.isValid(), "randomScalar1 should be valid");
        assertTrue(randomScalar2.isValid(), "randomScalar2 should be valid");
        assertNotEquals(randomScalar1, randomScalar2, "random scalars shouldn't be equal");
        assertNotEquals(randomScalar1, field.newOneElement(), "random scalar shouldn't equal 1");
        assertNotEquals(randomScalar1, field.newZeroElement(), "random scalar shouldn't equal 0");
        assertNotEquals(randomScalar2, field.newOneElement(), "random scalar shouldn't equal 1");
        assertNotEquals(randomScalar2, field.newZeroElement(), "random scalar shouldn't equal 0");
    }

    @Test
    @DisplayName("newRandomScalar from same seed are equal")
    void newRandomScalarDeterministic() {
        final byte[] seed = RandomUtils.randomByteArray(random, field.getSeedSize());

        assertEquals(field.newElementFromSeed(seed), field.newElementFromSeed(seed),
                "scalars from the same seed should be equal");
    }

    @Test
    @DisplayName("newRandomScalar with bad seed returns error code")
    void newRandomScalarBadSeed() {
        final byte[] smallSeed = RandomUtils.randomByteArray(random, field.getSeedSize() - 1);
        final byte[] largeSeed = RandomUtils.randomByteArray(random, field.getSeedSize() + 1);

        assertThrows(IllegalArgumentException.class, () -> field.newElementFromSeed(smallSeed),
                "small seed should yield null");
        assertThrows(IllegalArgumentException.class, () -> field.newElementFromSeed(largeSeed),
                "large seed should yield null");
    }

    @Test
    @DisplayName("newScalarFromInt with different integers produces unique results")
    void newScalarFromIntUnique() {
        final FieldElement scalar1 = field.newElement(11);
        final FieldElement scalar2 = field.newElement(33);

        assertNotEquals(scalar1, scalar2, "scalars shouldn't be equal");

        assertTrue(scalar1.isValid(), "scalar1 should be valid");
        assertTrue(scalar2.isValid(), "scalar2 should be valid");
        assertNotEquals(scalar1, field.newOneElement(), "scalar from int shouldn't equal 1");
        assertNotEquals(scalar1, field.newZeroElement(), "scalar from int shouldn't equal 0");
        assertNotEquals(scalar2, field.newOneElement(), "scalar from int shouldn't equal 1");
        assertNotEquals(scalar2, field.newZeroElement(), "scalar from int shouldn't equal 0");
    }

    @Test
    @DisplayName("newScalarFromInt succeeds with min and max int values")
    void newScalarFromIntExtremes() {
        assertTrue(field.newElement(Integer.MAX_VALUE).isValid(), "max scalar should be valid");
        assertTrue(field.newElement(Integer.MIN_VALUE).isValid(), "min scalar should be valid");
    }

    @Test
    @DisplayName("newScalarFromInt from same integer are equal")
    void newScalarFromIntDeterministic() {
        assertEquals(field.newElement(44), field.newElement(44), "scalars from the same int should be equal");
    }

    @Test
    @DisplayName("newZeroScalar produces the same result every time")
    void newZeroScalarDeterministic() {
        assertTrue(field.newZeroElement().isValid(), "0 scalar should be valid");
        assertEquals(field.newZeroElement(), field.newZeroElement(), "0 should equal 0");
        assertEquals(field.newZeroElement(), field.newElement(0), "0 should equal 0");
    }

    @Test
    @DisplayName("newOneScalar produces the same result every time")
    void newOneScalarDeterministic() {
        assertNotNull(field.newOneElement(), "1 scalar should be valid");
        assertEquals(field.newOneElement(), field.newOneElement(), "1 should equal 1");
        assertEquals(field.newOneElement(), field.newElement(1), "1 should equal 1");
    }

    @Test
    @DisplayName("newZeroScalar and newOneScalar are different")
    void differentZeroOne() {
        assertNotEquals(field.newZeroElement(), field.newOneElement(), "0 shouldn't equal 1");
    }

    @Test
    @DisplayName("Add modifies scalar")
    void scalarAddSuccess() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement sum = randomScalar1.add(randomScalar2);

        assertNotEquals(null, sum, "sum should be valid");
        assertNotEquals(sum, randomScalar1, "sum shouldn't equal randomScalar1");
        assertNotEquals(sum, randomScalar2, "sum shouldn't equal randomScalar2");
    }

    @Test
    @DisplayName("scalarAdd with null argument throws error")
    void scalarAddFailure() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        assertThrows(IllegalArgumentException.class, () -> randomScalar.add(null),
                "Null argument should cause error");
    }

    @Test
    @DisplayName("Adding 1 modifies scalar")
    void scalarAddOne() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement sum = randomScalar.add(field.newOneElement());

        assertNotEquals(null, sum, "sum should be valid");
        assertNotEquals(sum, randomScalar, "adding 1 should have an effect");
    }

    @Test
    @DisplayName("Adding 0 doesn't modify scalar")
    void scalarAddZero() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement sum = randomScalar.add(field.newZeroElement());

        assertNotEquals(null, sum, "sum should be valid");
        assertEquals(sum, randomScalar, "adding 0 shouldn't have an effect");
    }

    @Test
    @DisplayName("scalarAdd produces the same result every time for identical inputs")
    void scalarAddDeterministic() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement sum1 = randomScalar1.add(randomScalar2);
        final FieldElement sum2 = randomScalar1.add(randomScalar2);

        assertNotEquals(null, sum1, "sum1 should be valid");
        assertNotEquals(null, sum2, "sum2 should be valid");
        assertEquals(sum1, sum2, "addition with same inputs should produce same result");
    }

    @Test
    @DisplayName("scalarAdd produces the same result when swapping operands")
    void scalarAddCommutative() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement sum1 = randomScalar1.add(randomScalar2);
        final FieldElement sum2 = randomScalar2.add(randomScalar1);

        assertNotEquals(null, sum1, "sum1 should be valid");
        assertNotEquals(null, sum2, "sum2 should be valid");
        assertEquals(sum1, sum2, "addition with swapped inputs should produce same result");
    }

    @Test
    @DisplayName("Subtract modifies scalar")
    void scalarSubtractSuccess() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement difference = randomScalar1.subtract(randomScalar2);

        assertNotEquals(null, difference, "difference should be valid");
        assertNotEquals(difference, randomScalar1, "difference shouldn't equal randomScalar1");
        assertNotEquals(difference, randomScalar2, "difference shouldn't equal randomScalar2");
    }

    @Test
    @DisplayName("scalarSubtract with null arguments throws error")
    void scalarSubtractFailure() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        assertThrows(IllegalArgumentException.class, () -> randomScalar.subtract(null),
                "Null argument should cause error");
    }

    @Test
    @DisplayName("Subtracting 1 modifies scalar")
    void scalarSubtractOne() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement difference = randomScalar.subtract(field.newOneElement());

        assertNotEquals(null, difference, "difference should be valid");
        assertNotEquals(difference, randomScalar, "subtracting 1 should have an effect");
    }

    @Test
    @DisplayName("Subtracting 0 doesn't modify scalar")
    void scalarSubtractZero() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement difference = randomScalar.subtract(field.newZeroElement());

        assertNotEquals(null, difference, "difference should be valid");
        assertEquals(difference, randomScalar, "subtracting 0 shouldn't have an effect");
    }

    @Test
    @DisplayName("scalarSubtract produces the same result every time for identical inputs")
    void scalarSubtractDeterministic() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement difference1 = randomScalar1.subtract(randomScalar2);
        final FieldElement difference2 = randomScalar1.subtract(randomScalar2);

        assertNotEquals(null, difference1, "difference1 should be valid");
        assertNotEquals(null, difference2, "difference2 should be valid");
        assertEquals(difference1, difference2, "subtraction with same inputs should produce same result");
    }

    @Test
    @DisplayName("Multiply modifies scalar")
    void scalarMultiplySuccess() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement product = randomScalar1.multiply(randomScalar2);

        assertNotEquals(null, product, "product should be valid");
        assertNotEquals(product, randomScalar1, "product shouldn't equal randomScalar1");
        assertNotEquals(product, randomScalar2, "product shouldn't equal randomScalar2");
    }

    @Test
    @DisplayName("scalarMultiply with null arguments throws error")
    void scalarMultiplyFailure() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        assertThrows(IllegalArgumentException.class, () -> randomScalar.multiply(null),
                "Null argument should cause error");
    }

    @Test
    @DisplayName("Multiplying by 1 doesn't modify scalar")
    void scalarMultiplyByOne() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement product = randomScalar.multiply(field.newOneElement());

        assertNotEquals(null, product, "product should be valid");
        assertEquals(product, randomScalar, "multiplying by 1 shouldn't have an effect");
    }

    @Test
    @DisplayName("Multiplying by 0 produces 0")
    void scalarMultiplyByZero() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement product = randomScalar.multiply(field.newZeroElement());

        assertNotEquals(null, product, "product should be valid");
        assertEquals(product, field.newZeroElement(), "multiplying by 0 should produce 0");
    }

    @Test
    @DisplayName("scalarMultiply produces the same result every time for identical inputs")
    void scalarMultiplyDeterministic() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement product1 = randomScalar1.multiply(randomScalar2);
        final FieldElement product2 = randomScalar1.multiply(randomScalar2);

        assertNotEquals(null, product1, "product1 should be valid");
        assertNotEquals(null, product2, "product2 should be valid");
        assertEquals(product1, product2, "multiplication with same inputs should produce same result");
    }

    @Test
    @DisplayName("scalarMultiply produces the same result when swapping operands")
    void scalarMultiplyCommutative() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement product1 = randomScalar1.multiply(randomScalar2);
        final FieldElement product2 = randomScalar2.multiply(randomScalar1);

        assertNotEquals(null, product1, "product1 should be valid");
        assertNotEquals(null, product2, "product2 should be valid");
        assertEquals(product1, product2, "multiplication with swapped inputs should produce same result");
    }

    @Test
    @DisplayName("Divide modifies scalar")
    void scalarDivideSuccess() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement quotient = randomScalar1.divide(randomScalar2);

        assertNotEquals(null, quotient, "quotient should be valid");
        assertNotEquals(quotient, randomScalar1, "quotient shouldn't equal randomScalar1");
        assertNotEquals(quotient, randomScalar2, "quotient shouldn't equal randomScalar2");
    }

    @Test
    @DisplayName("scalarDivide with null arguments throws error")
    void scalarDivideFailure() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        assertThrows(IllegalArgumentException.class, () -> randomScalar.divide(null),
                "Null argument should cause error");
    }

    @Test
    @DisplayName("Dividing by 1 doesn't modify scalar")
    void scalarDivideByOne() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement quotient = randomScalar.divide(field.newOneElement());

        assertNotEquals(null, quotient, "quotient should be valid");
        assertEquals(quotient, randomScalar, "dividing by 1 shouldn't have an effect");
    }

    @Test
    @DisplayName("Dividing by 0 causes error")
    void scalarDivideByZero() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        assertThrows(BLS12381Exception.class, () -> randomScalar.divide(field.newZeroElement()),
                "Dividing by zero should cause error");
    }

    @Test
    @DisplayName("scalarDivide produces the same result every time for identical inputs")
    void scalarDivideDeterministic() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement quotient1 = randomScalar1.divide(randomScalar2);
        final FieldElement quotient2 = randomScalar1.divide(randomScalar2);

        assertNotEquals(null, quotient1, "quotient1 should be valid");
        assertNotEquals(null, quotient2, "quotient2 should be valid");
        assertEquals(quotient1, quotient2, "division with same inputs should produce same result");
    }

    @Test
    @DisplayName("Power modifies scalar")
    void scalarPowerSuccess() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement result = randomScalar.power(new BigInteger("99"));

        assertNotEquals(null, result, "result should be valid");
        assertNotEquals(result, randomScalar, "power shouldn't equal randomScalar");
    }

    @Test
    @DisplayName("scalarPower with null arguments throws error")
    void scalarPowerFailure() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        assertThrows(IllegalArgumentException.class, () ->
                        randomScalar.power(null),
                "Null exponent should cause error");
    }

    @Test
    @DisplayName("A scalar to the power of 1 doesn't modify scalar")
    void scalarPowerByOne() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement result = randomScalar.power(new BigInteger("1"));

        assertNotEquals(null, result, "result should be valid");
        assertEquals(result, randomScalar, "a scalar to the power of 1 shouldn't have an effect");
    }

    @Test
    @DisplayName("A scalar to the power of 0 is 1")
    void scalarPowerByZero() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement result = randomScalar.power(new BigInteger("0"));

        assertNotEquals(null, result, "result should be valid");
        assertEquals(result, field.newOneElement(), "a scalar to the power of 0 should equal 1");
    }

    @Test
    @DisplayName("scalarPower produces the same result every time for identical inputs")
    void scalarPowerDeterministic() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final BigInteger bigInt = new BigInteger("77");

        final FieldElement result1 = randomScalar.power(bigInt);
        final FieldElement result2 = randomScalar.power(bigInt);

        assertNotEquals(null, result1, "result1 should be valid");
        assertNotEquals(null, result2, "result2 should be valid");
        assertEquals(result1, result2, "power with same inputs should produce same result");
    }

    @Test
    @DisplayName("Subtract negates add")
    void subtractNegatesAdd() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement sum = randomScalar1.add(randomScalar2);
        final FieldElement difference = sum.subtract(randomScalar2);

        assertNotEquals(null, sum, "sum should be valid");
        assertNotEquals(null, difference, "difference should be valid");
        assertEquals(difference, randomScalar1, "subtraction should negate addition");
    }

    @Test
    @DisplayName("Add negates subtract")
    void addNegatesSubtract() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement difference = randomScalar1.subtract(randomScalar2);
        final FieldElement sum = difference.add(randomScalar2);

        assertNotEquals(null, difference, "difference should be valid");
        assertNotEquals(null, sum, "sum should be valid");
        assertEquals(sum, randomScalar1, "addition should negate subtraction");
    }

    @Test
    @DisplayName("divide negates multiply")
    void divideNegatesMultiply() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement product = randomScalar1.multiply(randomScalar2);
        final FieldElement quotient = product.divide(randomScalar2);

        assertNotEquals(null, product, "product should be valid");
        assertNotEquals(null, quotient, "quotient should be valid");
        assertEquals(quotient, randomScalar1, "divide should negate multiply");
    }

    @Test
    @DisplayName("Multiply negates divide")
    void multiplyNegatesDivide() {
        final FieldElement randomScalar1 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));
        final FieldElement randomScalar2 = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement quotient = randomScalar1.divide(randomScalar2);
        final FieldElement product = quotient.multiply(randomScalar2);

        assertNotEquals(null, quotient, "quotient should be valid");
        assertNotEquals(null, product, "product should be valid");
        assertEquals(product, randomScalar1, "multiply should negate divide");
    }

    @Test
    @DisplayName("Divide maps to power")
    void divideMapsToPower() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        // Take scalar to a power of 2
        final FieldElement power = randomScalar.power(new BigInteger("2"));
        final FieldElement quotient = power.divide(randomScalar);

        assertNotEquals(null, power, "power should be valid");
        assertNotEquals(null, quotient, "quotient should be valid");
        assertEquals(quotient, randomScalar, "divide should map to power");
    }

    @Test
    @DisplayName("Add maps to multiply")
    void addMapsToMultiply() {
        final FieldElement randomScalar = field.newElementFromSeed(
                RandomUtils.randomByteArray(random, field.getSeedSize()));

        final FieldElement sum = randomScalar.add(randomScalar);
        final FieldElement product = randomScalar.multiply(field.newElement(2));

        assertNotEquals(null, sum, "sum should be valid");
        assertNotEquals(null, product, "product should be valid");
        assertEquals(sum, product, "add should map to multiply");
    }

    @Test
    @DisplayName("scalarEquals with null arguments returns false")
    void scalarEqualsInvalid() {
        assertNotEquals(null, field.newElementFromSeed(RandomUtils.randomByteArray(random, field.getSeedSize())),
                "One value being null should return false");
    }

    @Test
    @DisplayName("checkScalarValidity valid")
    void checkScalarValidityValid() {
        assertTrue(field.newElementFromSeed(
                        RandomUtils.randomByteArray(random, field.getSeedSize())).isValid(),
                "scalar should be valid");
    }

    @Test
    @DisplayName("checkScalarValidity invalid")
    void checkScalarValidityInvalid() {
        final byte[] invalidElementBytes = new byte[32];
        Arrays.fill(invalidElementBytes, (byte) 0xFF);

        final FieldElement invalidElement = new BLS12381FieldElement(invalidElementBytes, new BLS12381Field());

        assertFalse(invalidElement.isValid(), "scalar should be invalid");
    }
}
