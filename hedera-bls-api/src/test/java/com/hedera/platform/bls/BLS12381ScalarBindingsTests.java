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

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("BLS12_381 Scalar Bindings Unit Tests")
class BLS12381ScalarBindingsTests {
	@Test
	@DisplayName("newRandomScalar with unique seeds produces unique results")
	void newRandomScalarUnique() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		JNITestUtils.assertScalarNotEquals(randomScalar1, randomScalar2, "random scalars shouldn't be equal");

		JNITestUtils.assertScalarNotEquals(randomScalar1, JNITestUtils.getOneScalar(),
				"random scalar shouldn't equal 1");
		JNITestUtils.assertScalarNotEquals(randomScalar1, JNITestUtils.getZeroScalar(),
				"random scalar shouldn't equal 0");
		JNITestUtils.assertScalarNotEquals(randomScalar2, JNITestUtils.getOneScalar(),
				"random scalar shouldn't equal 1");
		JNITestUtils.assertScalarNotEquals(randomScalar2, JNITestUtils.getZeroScalar(),
				"random scalar shouldn't equal 0");
	}

	@Test
	@DisplayName("newRandomScalar from same seed are equal")
	void newRandomScalarDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final byte[] seed = RandomUtils.randomByteArray(random, 32);

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getRandomScalar(seed),
				JNITestUtils.getRandomScalar(seed),
				"scalars from the same seed should be equal");
	}

	@Test
	@DisplayName("newRandomScalar with bad seed returns error code")
	void newRandomScalarBadSeed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		assertEquals(1, BLS12381ScalarBindings.newRandomScalar(RandomUtils.randomByteArray(random, 31), output));
		assertEquals(1, BLS12381ScalarBindings.newRandomScalar(RandomUtils.randomByteArray(random, 33), output));
	}

	@Test
	@DisplayName("newScalarFromInt with different integers produces unique results")
	void newScalarFromIntUnique() {
		final BLS12381FieldElement scalar1 = JNITestUtils.getScalarFromInt(11);
		final BLS12381FieldElement scalar2 = JNITestUtils.getScalarFromInt(33);

		JNITestUtils.assertScalarNotEquals(scalar1, scalar2, "scalars shouldn't be equal");

		JNITestUtils.assertScalarNotEquals(scalar1, JNITestUtils.getOneScalar(), "scalar from int shouldn't equal 1");
		JNITestUtils.assertScalarNotEquals(scalar1, JNITestUtils.getZeroScalar(), "scalar from int shouldn't equal 0");
		JNITestUtils.assertScalarNotEquals(scalar2, JNITestUtils.getOneScalar(), "scalar from int shouldn't equal 1");
		JNITestUtils.assertScalarNotEquals(scalar2, JNITestUtils.getZeroScalar(), "scalar from int shouldn't equal 0");
	}

	@Test
	@DisplayName("newScalarFromInt succeeds with min and max int values")
	void newScalarFromIntExtremes() {
		JNITestUtils.getScalarFromInt(Integer.MAX_VALUE);
		JNITestUtils.getScalarFromInt(Integer.MIN_VALUE);
	}

	@Test
	@DisplayName("newScalarFromInt for same integer are equal")
	void newScalarFromIntDeterministic() {
		JNITestUtils.assertScalarEquals(JNITestUtils.getScalarFromInt(44), JNITestUtils.getScalarFromInt(44),
				"scalars from the same int should be equal");
	}

	@Test
	@DisplayName("newZeroScalar produces the same result every time")
	void newZeroScalarDeterministic() {
		JNITestUtils.assertScalarEquals(JNITestUtils.getZeroScalar(), JNITestUtils.getZeroScalar(), "0 should equal 0");
		JNITestUtils.assertScalarEquals(JNITestUtils.getZeroScalar(), JNITestUtils.getScalarFromInt(0),
				"0 should equal 0");
	}

	@Test
	@DisplayName("newOneScalar produces the same result every time")
	void newOneScalarDeterministic() {
		JNITestUtils.assertScalarEquals(JNITestUtils.getOneScalar(), JNITestUtils.getOneScalar(), "1 should equal 1");
		JNITestUtils.assertScalarEquals(JNITestUtils.getOneScalar(), JNITestUtils.getScalarFromInt(1),
				"1 should equal 1");
	}

	@Test
	@DisplayName("newZeroScalar and newOneScalar are different")
	void differentZeroOne() {
		JNITestUtils.assertScalarNotEquals(JNITestUtils.getZeroScalar(), JNITestUtils.getOneScalar(),
				"0 shouldn't equal 1");
	}

	@Test
	@DisplayName("Add modifies scalar")
	void scalarAddSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		final BLS12381FieldElement sum = JNITestUtils.getScalarFromCall(
				BLS12381ScalarBindings.scalarAdd(randomScalar1, randomScalar2));

		JNITestUtils.assertScalarNotEquals(sum, randomScalar1, "sum shouldn't equal randomScalar1");
		JNITestUtils.assertScalarNotEquals(sum, randomScalar2, "sum shouldn't equal randomScalar2");
	}

	@Test
	@DisplayName("scalarAdd with null arguments throws error")
	void scalarAddFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarAdd(
				JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null), 1);
		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarAdd(
				null, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))), 1);
	}

	@Test
	@DisplayName("Adding 1 modifies scalar")
	void scalarAddOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertScalarNotEquals(
				JNITestUtils.getScalarFromCall(
						BLS12381ScalarBindings.scalarAdd(randomScalar, JNITestUtils.getOneScalar())),
				randomScalar,
				"adding 1 should have an effect");
	}

	@Test
	@DisplayName("Adding 0 doesn't modify scalar")
	void scalarAddZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(
						BLS12381ScalarBindings.scalarAdd(randomScalar, JNITestUtils.getZeroScalar())),
				randomScalar,
				"adding 0 shouldn't have an effect");
	}

	@Test
	@DisplayName("scalarAdd produces the same result every time for identical inputs")
	void scalarAddDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarAdd(randomScalar1, randomScalar2)),
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarAdd(randomScalar1, randomScalar2)),
				"addition with same inputs should produce same result");
	}

	@Test
	@DisplayName("Subtract modifies scalar")
	void scalarSubtractSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		final BLS12381FieldElement difference = JNITestUtils.getScalarFromCall(
				BLS12381ScalarBindings.scalarSubtract(randomScalar1, randomScalar2));

		JNITestUtils.assertScalarNotEquals(difference, randomScalar1, "difference shouldn't equal randomScalar1");
		JNITestUtils.assertScalarNotEquals(difference, randomScalar2, "difference shouldn't equal randomScalar2");
	}

	@Test
	@DisplayName("scalarSubtract with null arguments throws error")
	void scalarSubtractFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarSubtract(
				JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null), 1);
		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarSubtract(
				null, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))), 1);
	}

	@Test
	@DisplayName("Subtracting 1 modifies scalar")
	void scalarSubtractOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertScalarNotEquals(
				JNITestUtils.getScalarFromCall(
						BLS12381ScalarBindings.scalarSubtract(randomScalar, JNITestUtils.getOneScalar())),
				randomScalar,
				"subtracting 1 should have an effect");
	}

	@Test
	@DisplayName("Subtracting 0 doesn't modify scalar")
	void scalarSubtractZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(
						BLS12381ScalarBindings.scalarSubtract(randomScalar, JNITestUtils.getZeroScalar())),
				randomScalar,
				"subtracting 0 shouldn't have an effect");
	}

	@Test
	@DisplayName("scalarSubtract produces the same result every time for identical inputs")
	void scalarSubtractDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarSubtract(randomScalar1, randomScalar2)),
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarSubtract(randomScalar1, randomScalar2)),
				"subtraction with same inputs should produce same result");
	}

	@Test
	@DisplayName("Multiply modifies scalar")
	void scalarMultiplySuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		final BLS12381FieldElement product = JNITestUtils.getScalarFromCall(
				BLS12381ScalarBindings.scalarMultiply(randomScalar1, randomScalar2));

		JNITestUtils.assertScalarNotEquals(product, randomScalar1, "product shouldn't equal randomScalar1");
		JNITestUtils.assertScalarNotEquals(product, randomScalar2, "product shouldn't equal randomScalar2");
	}

	@Test
	@DisplayName("scalarMultiply with null arguments throws error")
	void scalarMultiplyFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarMultiply(
				JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null), 1);
		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarMultiply(
				null, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))), 1);
	}

	@Test
	@DisplayName("Multiplying by 1 doesn't modify scalar")
	void scalarMultiplyByOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(
						BLS12381ScalarBindings.scalarMultiply(randomScalar, JNITestUtils.getOneScalar())),
				randomScalar,
				"multiplying by 1 shouldn't have an effect");
	}

	@Test
	@DisplayName("Multiplying by 0 produces 0")
	void scalarMultiplyByZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(
						BLS12381ScalarBindings.scalarMultiply(randomScalar, JNITestUtils.getZeroScalar())),
				JNITestUtils.getZeroScalar(),
				"multiplying by 0 should produce 0");
	}

	@Test
	@DisplayName("scalarMultiply produces the same result every time for identical inputs")
	void scalarMultiplyDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarMultiply(randomScalar1, randomScalar2)),
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarMultiply(randomScalar1, randomScalar2)),
				"multiplication with same inputs should produce same result");
	}

	@Test
	@DisplayName("Divide modifies scalar")
	void scalarDivideSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		final BLS12381FieldElement quotient = JNITestUtils.getScalarFromCall(
				BLS12381ScalarBindings.scalarDivide(randomScalar1, randomScalar2));

		JNITestUtils.assertScalarNotEquals(quotient, randomScalar1, "quotient shouldn't equal randomScalar1");
		JNITestUtils.assertScalarNotEquals(quotient, randomScalar2, "quotient shouldn't equal randomScalar2");
	}

	@Test
	@DisplayName("scalarDivide with null arguments throws error")
	void scalarDivideFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarDivide(
				JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null), 1);
		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarDivide(
				null, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))), 1);
	}

	@Test
	@DisplayName("Dividing by 1 doesn't modify scalar")
	void scalarDivideByOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(
						BLS12381ScalarBindings.scalarDivide(randomScalar, JNITestUtils.getOneScalar())),
				randomScalar,
				"dividing by 1 shouldn't have an effect");
	}

	@Test
	@DisplayName("Dividing by 0 causes error")
	void scalarDivideByZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarDivide(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)),
						JNITestUtils.getZeroScalar()),
				6);
	}

	@Test
	@DisplayName("scalarDivide produces the same result every time for identical inputs")
	void scalarDivideDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarDivide(randomScalar1, randomScalar2)),
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarDivide(randomScalar1, randomScalar2)),
				"division with same inputs should produce same result");
	}

	@Test
	@DisplayName("Power modifies scalar")
	void scalarPowerSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertScalarNotEquals(
				JNITestUtils.getScalarFromCall(
						BLS12381ScalarBindings.scalarPower(randomScalar, new BigInteger("99").toByteArray())),
				randomScalar,
				"power shouldn't equal randomScalar");
	}

	@Test
	@DisplayName("scalarPower with null arguments throws error")
	void scalarPowerFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarPower(
				JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null), 1);
		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarPower(
				null, new BigInteger("1").toByteArray()), 1);
	}

	@Test
	@DisplayName("A scalar to the power of 1 doesn't modify scalar")
	void scalarPowerByOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(
						BLS12381ScalarBindings.scalarPower(randomScalar, new BigInteger("1").toByteArray())),
				randomScalar,
				"a scalar to the power of 1 shouldn't have an effect");
	}

	@Test
	@DisplayName("A scalar to the power of 0 is 1")
	void scalarPowerByZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarPower(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)),
						new BigInteger("0").toByteArray())),
				JNITestUtils.getOneScalar(),
				"a scalar to the power of 0 should equal 1");
	}

	@Test
	@DisplayName("scalarPower produces the same result every time for identical inputs")
	void scalarPowerDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));
		final byte[] bigInt = new BigInteger("77").toByteArray();

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarPower(randomScalar, bigInt)),
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarPower(randomScalar, bigInt)),
				"power with same inputs should produce same result");
	}

	@Test
	@DisplayName("Subtract negates add")
	void subtractNegatesAdd() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		final BLS12381FieldElement sum = JNITestUtils.getScalarFromCall(
				BLS12381ScalarBindings.scalarAdd(randomScalar1, randomScalar2));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarSubtract(sum, randomScalar2)),
				randomScalar1,
				"subtraction should negate addition");
	}

	@Test
	@DisplayName("Add negates subtract")
	void addNegatesSubtract() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		final BLS12381FieldElement difference = JNITestUtils.getScalarFromCall(
				BLS12381ScalarBindings.scalarSubtract(randomScalar1, randomScalar2));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarAdd(difference, randomScalar2)),
				randomScalar1,
				"addition should negate subtraction");
	}

	@Test
	@DisplayName("divide negates multiply")
	void divideNegatesMultiply() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		final BLS12381FieldElement product = JNITestUtils.getScalarFromCall(
				BLS12381ScalarBindings.scalarMultiply(randomScalar1, randomScalar2));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarDivide(product, randomScalar2)),
				randomScalar1,
				"divide should negate multiply");
	}

	@Test
	@DisplayName("Multiply negates divide")
	void multiplyNegatesDivide() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar1 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));
		final BLS12381FieldElement randomScalar2 = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random,
				32));

		final BLS12381FieldElement quotient = JNITestUtils.getScalarFromCall(
				BLS12381ScalarBindings.scalarDivide(randomScalar1, randomScalar2));

		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarMultiply(quotient, randomScalar2)),
				randomScalar1,
				"multiply should negate divide");
	}

	@Test
	@DisplayName("Divide maps to power")
	void divideMapsToPower() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		// Take scalar to a power of 2
		final BLS12381FieldElement power = JNITestUtils.getScalarFromCall(
				BLS12381ScalarBindings.scalarPower(randomScalar, new BigInteger("2").toByteArray()));

		// Divide scalar^2 by scalar
		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarDivide(power, randomScalar)),
				randomScalar,
				"divide should map to power");
	}

	@Test
	@DisplayName("Add maps to multiply")
	void addMapsToMultiply() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement scalarTwo = JNITestUtils.getScalarFromInt(2);

		final BLS12381FieldElement sum = JNITestUtils.getScalarFromCall(
				BLS12381ScalarBindings.scalarAdd(randomScalar, randomScalar));

		// Taking the sum of the same element multiple times is equivalent to multiplying
		JNITestUtils.assertScalarEquals(
				JNITestUtils.getScalarFromCall(BLS12381ScalarBindings.scalarMultiply(randomScalar, scalarTwo)),
				sum,
				"add should map to multiply");
	}

	@Test
	@DisplayName("scalarEquals with null arguments throws error")
	void scalarEqualsFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarEquals(
				JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)), null), 1);
		JNITestUtils.assertErrorFromCall(BLS12381ScalarBindings.scalarEquals(
				null, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))), 1);
	}

	@Test
	@DisplayName("checkScalarValidity valid")
	void checkScalarValidityValid() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertBooleanCallTrue(BLS12381ScalarBindings.checkScalarValidity(
						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))),
				"scalar should be valid");
	}

	@Test
	@DisplayName("checkScalarValidity invalid")
	void checkScalarValidityInvalid() {
		final byte[] invalidElementBytes = new byte[32];
		Arrays.fill(invalidElementBytes, (byte) 0xFF);

		final BLS12381FieldElement invalidElement = new BLS12381FieldElement(invalidElementBytes, new BLS12381Field());

		JNITestUtils.assertBooleanCallFalse(BLS12381ScalarBindings.checkScalarValidity(invalidElement),
				"scalar should be invalid");
	}
}
