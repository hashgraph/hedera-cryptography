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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("BLS12_381 Scalar Bindings Unit Tests")
class BLS12381BindingsTests {
	@Test
	@DisplayName("newRandomScalar with unique seeds produces unique results")
	void newRandomScalarUnique() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		assertNotEquals(null, randomScalar1, "randomScalar1 should be valid");
		assertNotEquals(null, randomScalar2, "randomScalar2 should be valid");
		assertFalse(BLS12381Bindings.scalarEquals(randomScalar1, randomScalar2),
				"random scalars shouldn't be equal");
		assertFalse(BLS12381Bindings.scalarEquals(randomScalar1, JNITestUtils.getOneScalar()),
				"random scalar shouldn't equal 1");
		assertFalse(BLS12381Bindings.scalarEquals(randomScalar1, JNITestUtils.getZeroScalar()),
				"random scalar shouldn't equal 0");
		assertFalse(BLS12381Bindings.scalarEquals(randomScalar2, JNITestUtils.getOneScalar()),
				"random scalar shouldn't equal 1");
		assertFalse(BLS12381Bindings.scalarEquals(randomScalar2, JNITestUtils.getZeroScalar()),
				"random scalar shouldn't equal 0");
	}

	@Test
	@DisplayName("newRandomScalar from same seed are equal")
	void newRandomScalarDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final byte[] seed = RandomUtils.randomByteArray(random, 32);

		assertTrue(BLS12381Bindings.scalarEquals(
						JNITestUtils.getRandomScalar(seed),
						JNITestUtils.getRandomScalar(seed)),
				"scalars from the same seed should be equal");
	}

	@Test
	@DisplayName("newRandomScalar with bad seed returns error code")
	void newRandomScalarBadSeed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		assertNotEquals(0, BLS12381Bindings.newRandomScalar(RandomUtils.randomByteArray(random, 31), output));
		assertNotEquals(0, BLS12381Bindings.newRandomScalar(RandomUtils.randomByteArray(random, 33), output));
	}

	@Test
	@DisplayName("newScalarFromInt with different integers produces unique results")
	void newScalarFromIntUnique() {
		final BLS12381FieldElement scalar1 = JNITestUtils.getScalarFromInt(11);
		final BLS12381FieldElement scalar2 = JNITestUtils.getScalarFromInt(33);

		assertFalse(BLS12381Bindings.scalarEquals(scalar1, scalar2), "scalars shouldn't be equal");

		assertNotEquals(null, scalar1, "scalar1 should be valid");
		assertNotEquals(null, scalar2, "scalar2 should be valid");
		assertFalse(BLS12381Bindings.scalarEquals(scalar1, JNITestUtils.getOneScalar()),
				"scalar from int shouldn't equal 1");
		assertFalse(BLS12381Bindings.scalarEquals(scalar1, JNITestUtils.getZeroScalar()),
				"scalar from int shouldn't equal 0");
		assertFalse(BLS12381Bindings.scalarEquals(scalar2, JNITestUtils.getOneScalar()),
				"scalar from int shouldn't equal 1");
		assertFalse(BLS12381Bindings.scalarEquals(scalar2, JNITestUtils.getZeroScalar()),
				"scalar from int shouldn't equal 0");
	}

	@Test
	@DisplayName("newScalarFromInt succeeds with min and max int values")
	void newScalarFromIntExtremes() {
		JNITestUtils.getScalarFromInt(Integer.MAX_VALUE);
		JNITestUtils.getScalarFromInt(Integer.MIN_VALUE);
	}

	@Test
	@DisplayName("newScalarFromInt from same integer are equal")
	void newScalarFromIntDeterministic() {
		assertTrue(BLS12381Bindings.scalarEquals(
						JNITestUtils.getScalarFromInt(44), JNITestUtils.getScalarFromInt(44)),
				"scalars from the same int should be equal");
	}

	@Test
	@DisplayName("newZeroScalar produces the same result every time")
	void newZeroScalarDeterministic() {
		assertNotEquals(null, JNITestUtils.getZeroScalar(), "0 scalar should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(JNITestUtils.getZeroScalar(), JNITestUtils.getZeroScalar()),
				"0 should equal 0");
		assertTrue(BLS12381Bindings.scalarEquals(JNITestUtils.getZeroScalar(), JNITestUtils.getScalarFromInt(0)),
				"0 should equal 0");
	}

	@Test
	@DisplayName("newOneScalar produces the same result every time")
	void newOneScalarDeterministic() {
		assertNotEquals(null, JNITestUtils.getOneScalar(), "1 scalar should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(JNITestUtils.getOneScalar(), JNITestUtils.getOneScalar()),
				"1 should equal 1");
		assertTrue(BLS12381Bindings.scalarEquals(JNITestUtils.getOneScalar(), JNITestUtils.getScalarFromInt(1)),
				"1 should equal 1");
	}

	@Test
	@DisplayName("newZeroScalar and newOneScalar are different")
	void differentZeroOne() {
		assertFalse(BLS12381Bindings.scalarEquals(JNITestUtils.getZeroScalar(), JNITestUtils.getOneScalar()),
				"0 shouldn't equal 1");
	}

	@Test
	@DisplayName("Add modifies scalar")
	void scalarAddSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement sum = JNITestUtils.scalarAdd(randomScalar1, randomScalar2);

		assertNotEquals(null, sum, "sum should be valid");
		assertFalse(BLS12381Bindings.scalarEquals(sum, randomScalar1), "sum shouldn't equal randomScalar1");
		assertFalse(BLS12381Bindings.scalarEquals(sum, randomScalar2), "sum shouldn't equal randomScalar2");
	}

	@Test
	@DisplayName("scalarAdd with null arguments throws error")
	void scalarAddFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertNull(JNITestUtils.scalarAdd(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null),
				"Null argument should cause error");
		assertNull(JNITestUtils.scalarAdd(
						null, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))),
				"Null argument should cause error");
	}

	@Test
	@DisplayName("Adding 1 modifies scalar")
	void scalarAddOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement sum = JNITestUtils.scalarAdd(randomScalar, JNITestUtils.getOneScalar());

		assertNotEquals(null, sum, "sum should be valid");
		assertFalse(BLS12381Bindings.scalarEquals(sum, randomScalar), "adding 1 should have an effect");
	}

	@Test
	@DisplayName("Adding 0 doesn't modify scalar")
	void scalarAddZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement sum = JNITestUtils.scalarAdd(randomScalar, JNITestUtils.getZeroScalar());

		assertNotEquals(null, sum, "sum should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(sum, randomScalar), "adding 0 shouldn't have an effect");
	}

	@Test
	@DisplayName("scalarAdd produces the same result every time for identical inputs")
	void scalarAddDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement sum1 = JNITestUtils.scalarAdd(randomScalar1, randomScalar2);
		final BLS12381FieldElement sum2 = JNITestUtils.scalarAdd(randomScalar1, randomScalar2);

		assertNotEquals(null, sum1, "sum1 should be valid");
		assertNotEquals(null, sum2, "sum2 should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(sum1, sum2),
				"addition with same inputs should produce same result");
	}

	@Test
	@DisplayName("scalarAdd produces the same result when swapping operands")
	void scalarAddCommutative() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement sum1 = JNITestUtils.scalarAdd(randomScalar1, randomScalar2);
		final BLS12381FieldElement sum2 = JNITestUtils.scalarAdd(randomScalar2, randomScalar1);

		assertNotEquals(null, sum1, "sum1 should be valid");
		assertNotEquals(null, sum2, "sum2 should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(sum1, sum2),
				"addition with swapped inputs should produce same result");
	}

	@Test
	@DisplayName("Subtract modifies scalar")
	void scalarSubtractSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement difference = JNITestUtils.scalarSubtract(randomScalar1, randomScalar2);

		assertNotEquals(null, difference, "difference should be valid");
		assertFalse(BLS12381Bindings.scalarEquals(difference, randomScalar1),
				"difference shouldn't equal randomScalar1");
		assertFalse(BLS12381Bindings.scalarEquals(difference, randomScalar2),
				"difference shouldn't equal randomScalar2");
	}

	@Test
	@DisplayName("scalarSubtract with null arguments throws error")
	void scalarSubtractFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertNull(JNITestUtils.scalarSubtract(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null),
				"Null argument should cause error");
		assertNull(JNITestUtils.scalarSubtract(
						null, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))),
				"Null argument should cause error");
	}

	@Test
	@DisplayName("Subtracting 1 modifies scalar")
	void scalarSubtractOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement difference = JNITestUtils.scalarSubtract(randomScalar, JNITestUtils.getOneScalar());

		assertNotEquals(null, difference, "difference should be valid");
		assertFalse(BLS12381Bindings.scalarEquals(difference, randomScalar),
				"subtracting 1 should have an effect");
	}

	@Test
	@DisplayName("Subtracting 0 doesn't modify scalar")
	void scalarSubtractZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement difference = JNITestUtils.scalarSubtract(randomScalar, JNITestUtils.getZeroScalar());

		assertNotEquals(null, difference, "difference should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(difference, randomScalar),
				"subtracting 0 shouldn't have an effect");
	}

	@Test
	@DisplayName("scalarSubtract produces the same result every time for identical inputs")
	void scalarSubtractDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement difference1 = JNITestUtils.scalarSubtract(randomScalar1, randomScalar2);
		final BLS12381FieldElement difference2 = JNITestUtils.scalarSubtract(randomScalar1, randomScalar2);

		assertNotEquals(null, difference1, "difference1 should be valid");
		assertNotEquals(null, difference2, "difference2 should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(difference1, difference2),
				"subtraction with same inputs should produce same result");
	}

	@Test
	@DisplayName("Multiply modifies scalar")
	void scalarMultiplySuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement product = JNITestUtils.scalarMultiply(randomScalar1, randomScalar2);

		assertNotEquals(null, product, "product should be valid");
		assertFalse(BLS12381Bindings.scalarEquals(product, randomScalar1),
				"product shouldn't equal randomScalar1");
		assertFalse(BLS12381Bindings.scalarEquals(product, randomScalar2),
				"product shouldn't equal randomScalar2");
	}

	@Test
	@DisplayName("scalarMultiply with null arguments throws error")
	void scalarMultiplyFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertNull(JNITestUtils.scalarMultiply(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null),
				"Null argument should cause error");
		assertNull(JNITestUtils.scalarMultiply(
						null, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))),
				"Null argument should cause error");
	}

	@Test
	@DisplayName("Multiplying by 1 doesn't modify scalar")
	void scalarMultiplyByOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement product = JNITestUtils.scalarMultiply(randomScalar, JNITestUtils.getOneScalar());

		assertNotEquals(null, product, "product should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(product, randomScalar),
				"multiplying by 1 shouldn't have an effect");
	}

	@Test
	@DisplayName("Multiplying by 0 produces 0")
	void scalarMultiplyByZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement product = JNITestUtils.scalarMultiply(randomScalar, JNITestUtils.getZeroScalar());

		assertNotEquals(null, product, "product should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(product, JNITestUtils.getZeroScalar()),
				"multiplying by 0 should produce 0");
	}

	@Test
	@DisplayName("scalarMultiply produces the same result every time for identical inputs")
	void scalarMultiplyDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement product1 = JNITestUtils.scalarMultiply(randomScalar1, randomScalar2);
		final BLS12381FieldElement product2 = JNITestUtils.scalarMultiply(randomScalar1, randomScalar2);

		assertNotEquals(null, product1, "product1 should be valid");
		assertNotEquals(null, product2, "product2 should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(product1, product2),
				"multiplication with same inputs should produce same result");
	}

	@Test
	@DisplayName("scalarMultiply produces the same result when swapping operands")
	void scalarMultiplyCommutative() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement product1 = JNITestUtils.scalarMultiply(randomScalar1, randomScalar2);
		final BLS12381FieldElement product2 = JNITestUtils.scalarMultiply(randomScalar2, randomScalar1);

		assertNotEquals(null, product1, "product1 should be valid");
		assertNotEquals(null, product2, "product2 should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(product1, product2),
				"multiplication with swapped inputs should produce same result");
	}

	@Test
	@DisplayName("Divide modifies scalar")
	void scalarDivideSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement quotient = JNITestUtils.scalarDivide(randomScalar1, randomScalar2);

		assertNotEquals(null, quotient, "quotient should be valid");
		assertFalse(BLS12381Bindings.scalarEquals(quotient, randomScalar1),
				"quotient shouldn't equal randomScalar1");
		assertFalse(BLS12381Bindings.scalarEquals(quotient, randomScalar2),
				"quotient shouldn't equal randomScalar2");
	}

	@Test
	@DisplayName("scalarDivide with null arguments throws error")
	void scalarDivideFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertNull(JNITestUtils.scalarDivide(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null),
				"Null argument should cause error");
		assertNull(JNITestUtils.scalarDivide(
						null, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))),
				"Null argument should cause error");
	}

	@Test
	@DisplayName("Dividing by 1 doesn't modify scalar")
	void scalarDivideByOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement quotient = JNITestUtils.scalarDivide(randomScalar, JNITestUtils.getOneScalar());

		assertNotEquals(null, quotient, "quotient should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(quotient, randomScalar),
				"dividing by 1 shouldn't have an effect");
	}

	@Test
	@DisplayName("Dividing by 0 causes error")
	void scalarDivideByZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertNull(JNITestUtils.scalarDivide(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)),
						JNITestUtils.getZeroScalar()),
				"Dividing by zero should cause error");
	}

	@Test
	@DisplayName("scalarDivide produces the same result every time for identical inputs")
	void scalarDivideDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement quotient1 = JNITestUtils.scalarDivide(randomScalar1, randomScalar2);
		final BLS12381FieldElement quotient2 = JNITestUtils.scalarDivide(randomScalar1, randomScalar2);

		assertNotEquals(null, quotient1, "quotient1 should be valid");
		assertNotEquals(null, quotient2, "quotient2 should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(quotient1, quotient2),
				"division with same inputs should produce same result");
	}

	@Test
	@DisplayName("Power modifies scalar")
	void scalarPowerSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement result = JNITestUtils.scalarPower(randomScalar, new BigInteger("99").toByteArray());

		assertNotEquals(null, result, "result should be valid");
		assertFalse(BLS12381Bindings.scalarEquals(result, randomScalar), "power shouldn't equal randomScalar");
	}

	@Test
	@DisplayName("scalarPower with null arguments throws error")
	void scalarPowerFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertNull(JNITestUtils.scalarPower(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null),
				"Null exponent should cause error");
		assertNull(JNITestUtils.scalarPower(null, new BigInteger("1").toByteArray()),
				"Null base should cause error");
	}

	@Test
	@DisplayName("A scalar to the power of 1 doesn't modify scalar")
	void scalarPowerByOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement result = JNITestUtils.scalarPower(randomScalar, new BigInteger("1").toByteArray());

		assertNotEquals(null, result, "result should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(result, randomScalar),
				"a scalar to the power of 1 shouldn't have an effect");
	}

	@Test
	@DisplayName("A scalar to the power of 0 is 1")
	void scalarPowerByZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement result = JNITestUtils.scalarPower(randomScalar, new BigInteger("0").toByteArray());

		assertNotEquals(null, result, "result should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(result, JNITestUtils.getOneScalar()),
				"a scalar to the power of 0 should equal 1");
	}

	@Test
	@DisplayName("scalarPower produces the same result every time for identical inputs")
	void scalarPowerDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));
		final byte[] bigInt = new BigInteger("77").toByteArray();

		final BLS12381FieldElement result1 = JNITestUtils.scalarPower(randomScalar, bigInt);
		final BLS12381FieldElement result2 = JNITestUtils.scalarPower(randomScalar, bigInt);

		assertNotEquals(null, result1, "result1 should be valid");
		assertNotEquals(null, result2, "result2 should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(result1, result2),
				"power with same inputs should produce same result");
	}

	@Test
	@DisplayName("Subtract negates add")
	void subtractNegatesAdd() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement sum = JNITestUtils.scalarAdd(randomScalar1, randomScalar2);
		final BLS12381FieldElement difference = JNITestUtils.scalarSubtract(sum, randomScalar2);

		assertNotEquals(null, sum, "sum should be valid");
		assertNotEquals(null, difference, "difference should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(difference, randomScalar1),
				"subtraction should negate addition");
	}

	@Test
	@DisplayName("Add negates subtract")
	void addNegatesSubtract() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement difference = JNITestUtils.scalarSubtract(randomScalar1, randomScalar2);
		final BLS12381FieldElement sum = JNITestUtils.scalarAdd(difference, randomScalar2);

		assertNotEquals(null, difference, "difference should be valid");
		assertNotEquals(null, sum, "sum should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(sum, randomScalar1), "addition should negate subtraction");
	}

	@Test
	@DisplayName("divide negates multiply")
	void divideNegatesMultiply() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement product = JNITestUtils.scalarMultiply(randomScalar1, randomScalar2);
		final BLS12381FieldElement quotient = JNITestUtils.scalarDivide(product, randomScalar2);

		assertNotEquals(null, product, "product should be valid");
		assertNotEquals(null, quotient, "quotient should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(quotient, randomScalar1), "divide should negate multiply");
	}

	@Test
	@DisplayName("Multiply negates divide")
	void multiplyNegatesDivide() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement quotient = JNITestUtils.scalarDivide(randomScalar1, randomScalar2);
		final BLS12381FieldElement product = JNITestUtils.scalarMultiply(quotient, randomScalar2);

		assertNotEquals(null, quotient, "quotient should be valid");
		assertNotEquals(null, product, "product should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(product, randomScalar1), "multiply should negate divide");
	}

	@Test
	@DisplayName("Divide maps to power")
	void divideMapsToPower() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		// Take scalar to a power of 2
		final BLS12381FieldElement power = JNITestUtils.scalarPower(randomScalar, new BigInteger("2").toByteArray());
		final BLS12381FieldElement quotient = JNITestUtils.scalarDivide(power, randomScalar);

		assertNotEquals(null, power, "power should be valid");
		assertNotEquals(null, quotient, "quotient should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(quotient, randomScalar), "divide should map to power");
	}

	@Test
	@DisplayName("Add maps to multiply")
	void addMapsToMultiply() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381FieldElement sum = JNITestUtils.scalarAdd(randomScalar, randomScalar);
		final BLS12381FieldElement product = JNITestUtils.scalarMultiply(
				randomScalar, JNITestUtils.getScalarFromInt(2));

		assertNotEquals(null, sum, "sum should be valid");
		assertNotEquals(null, product, "product should be valid");
		assertTrue(BLS12381Bindings.scalarEquals(sum, product), "add should map to multiply");
	}

	@Test
	@DisplayName("scalarEquals with null arguments returns false")
	void scalarEqualsInvalid() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertFalse(BLS12381Bindings.scalarEquals(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null),
				"One value being null should return false");
		assertFalse(BLS12381Bindings.scalarEquals(
						null, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))),
				"One value being null should return false");
	}

	@Test
	@DisplayName("checkScalarValidity valid")
	void checkScalarValidityValid() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertTrue(BLS12381Bindings.checkScalarValidity(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))),
				"scalar should be valid");
	}

	@Test
	@DisplayName("checkScalarValidity invalid")
	void checkScalarValidityInvalid() {
		final byte[] invalidElementBytes = new byte[32];
		Arrays.fill(invalidElementBytes, (byte) 0xFF);

		final BLS12381FieldElement invalidElement = new BLS12381FieldElement(invalidElementBytes, new BLS12381Field());

		assertFalse(BLS12381Bindings.checkScalarValidity(invalidElement), "scalar should be invalid");
	}
}
