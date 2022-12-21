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

import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("BLS12_381 Group 1 Bindings Unit Tests")
class BLS12381Group1BindingsTests {
	@Test
	@DisplayName("newRandomG1 with unique seeds produces unique results")
	void newRandomElementUnique() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		assertNotEquals(null, randomElement1, "randomElement1 should be valid");
		assertNotEquals(null, randomElement2, "randomElement2 should be valid");
		assertFalse(BLS12381Group1Bindings.g1ElementEquals(randomElement1, randomElement2),
				"random elements shouldn't be equal");
		assertFalse(BLS12381Group1Bindings.g1ElementEquals(randomElement1, JNITestUtils.getG1Identity()),
				"random element 1 shouldn't equal identity");
		assertFalse(BLS12381Group1Bindings.g1ElementEquals(randomElement2, JNITestUtils.getG1Identity()),
				"random element 2 shouldn't equal identity");
	}

	@Test
	@DisplayName("getG1RandomElement from same seed are equal")
	void newRandomElementDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final byte[] seed = RandomUtils.randomByteArray(random, 32);

		assertTrue(BLS12381Group1Bindings.g1ElementEquals(
						JNITestUtils.getG1RandomElement(seed),
						JNITestUtils.getG1RandomElement(seed)),
				"elements from the same seed should be equal");
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
		assertNotEquals(null, JNITestUtils.getG1Identity(), "identity should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(
						JNITestUtils.getG1Identity(), JNITestUtils.getG1Identity()),
				"identity should equal identity");
	}

	@Test
	@DisplayName("g1Divide success")
	void g1DivideSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element quotient = JNITestUtils.g1Divide(randomElement1, randomElement2);

		assertNotEquals(null, quotient, "quotient should be valid");
		assertFalse(BLS12381Group1Bindings.g1ElementEquals(quotient, randomElement1),
				"quotient shouldn't equal randomElement1");
		assertFalse(BLS12381Group1Bindings.g1ElementEquals(quotient, randomElement2),
				"quotient shouldn't equal randomElement2");
	}

	@Test
	@DisplayName("g1Divide compressed")
	void g1DivideCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element randomElement1Compressed = JNITestUtils.g1Compress(randomElement1);
		final BLS12381Group1Element randomElement2Compressed = JNITestUtils.g1Compress(randomElement2);

		final BLS12381Group1Element quotient = JNITestUtils.g1Divide(randomElement1, randomElement2);
		final BLS12381Group1Element quotientCompressed = JNITestUtils.g1Divide(
				randomElement1Compressed, randomElement2Compressed);
		final BLS12381Group1Element quotientMixed1 = JNITestUtils.g1Divide(
				randomElement1, randomElement2Compressed);
		final BLS12381Group1Element quotientMixed2 = JNITestUtils.g1Divide(
				randomElement1Compressed, randomElement2);

		assertNotEquals(null, quotient, "quotient should be valid");
		assertNotEquals(null, quotientCompressed, "quotientCompressed should be valid");
		assertNotEquals(null, quotientMixed1, "quotientMixed1 should be valid");
		assertNotEquals(null, quotientMixed2, "quotientMixed2 should be valid");

		assertTrue(BLS12381Group1Bindings.g1ElementEquals(quotient, quotientCompressed),
				"compression shouldn't affect result");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(quotient, quotientMixed1),
				"compression shouldn't affect result");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(quotient, quotientMixed2),
				"compression shouldn't affect result");
	}

	@Test
	@DisplayName("g1Divide with null arguments throws error")
	void g1DivideFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertNull(JNITestUtils.g1Divide(
						JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)), null),
				"Null argument should cause error");
		assertNull(JNITestUtils.g1Divide(
						null, JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32))),
				"Null argument should cause error");
	}

	@Test
	@DisplayName("Dividing by identity doesn't change element")
	void g1DivideByIdentity() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element quotient = JNITestUtils.g1Divide(randomElement, JNITestUtils.getG1Identity());

		assertNotEquals(null, quotient, "quotient should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(quotient, randomElement),
				"dividing by identity shouldn't have an effect");
	}

	@Test
	@DisplayName("g1Divide produces the same result every time for identical inputs")
	void g1DivideDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element quotient1 = JNITestUtils.g1Divide(randomElement1, randomElement2);
		final BLS12381Group1Element quotient2 = JNITestUtils.g1Divide(randomElement1, randomElement2);

		assertNotEquals(null, quotient1, "quotient1 should be valid");
		assertNotEquals(null, quotient2, "quotient2 should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(quotient1, quotient2),
				"division with same inputs should produce same result");
	}

	@Test
	@DisplayName("g1Multiply success")
	void g1MultiplySuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element product = JNITestUtils.g1Multiply(randomElement1, randomElement2);

		assertNotEquals(null, product, "product should be valid");
		assertFalse(BLS12381Group1Bindings.g1ElementEquals(product, randomElement1),
				"product shouldn't equal randomElement1");
		assertFalse(BLS12381Group1Bindings.g1ElementEquals(product, randomElement2),
				"product shouldn't equal randomElement2");
	}

	@Test
	@DisplayName("g1Multiply compressed")
	void g1MultiplyCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element randomElement1Compressed = JNITestUtils.g1Compress(randomElement1);
		final BLS12381Group1Element randomElement2Compressed = JNITestUtils.g1Compress(randomElement2);

		final BLS12381Group1Element product = JNITestUtils.g1Multiply(randomElement1, randomElement2);
		final BLS12381Group1Element productCompressed = JNITestUtils.g1Multiply(
				randomElement1Compressed, randomElement2Compressed);
		final BLS12381Group1Element productMixed1 = JNITestUtils.g1Multiply(
				randomElement1, randomElement2Compressed);
		final BLS12381Group1Element productMixed2 = JNITestUtils.g1Multiply(
				randomElement1Compressed, randomElement2);

		assertNotEquals(null, product, "product should be valid");
		assertNotEquals(null, productCompressed, "productCompressed should be valid");
		assertNotEquals(null, productMixed1, "productMixed1 should be valid");
		assertNotEquals(null, productMixed2, "productMixed2 should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product, productCompressed),
				"compression shouldn't affect result");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product, productMixed1),
				"compression shouldn't affect result");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product, productMixed2),
				"compression shouldn't affect result");
	}

	@Test
	@DisplayName("g1Multiply with null arguments throws error")
	void g1MultiplyFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertNull(JNITestUtils.g1Multiply(
						JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)), null),
				"Null argument should cause error");
		assertNull(JNITestUtils.g1Multiply(
						null, JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32))),
				"Null argument should cause error");
	}

	@Test
	@DisplayName("Multiplying by identity doesn't change element")
	void g1MultiplyByIdentity() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element product = JNITestUtils.g1Multiply(randomElement, JNITestUtils.getG1Identity());

		assertNotEquals(null, product, "product should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product, randomElement),
				"multiplying by identity shouldn't have an effect");
	}

	@Test
	@DisplayName("g1Multiply produces the same result every time for identical inputs")
	void g1MultiplyDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element product1 = JNITestUtils.g1Multiply(randomElement1, randomElement2);
		final BLS12381Group1Element product2 = JNITestUtils.g1Multiply(randomElement1, randomElement2);

		assertNotEquals(null, product1, "product1 should be valid");
		assertNotEquals(null, product2, "product2 should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product1, product2),
				"multiplication with same inputs should produce same result");
	}

	@Test
	@DisplayName("g1Multiply produces the same result when swapping operands")
	void g1MultiplyCommutative() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element product1 = JNITestUtils.g1Multiply(randomElement1, randomElement2);
		final BLS12381Group1Element product2 = JNITestUtils.g1Multiply(randomElement2, randomElement1);

		assertNotEquals(null, product1, "product1 should be valid");
		assertNotEquals(null, product2, "product2 should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product1, product2),
				"multiplication with swapped inputs should produce same result");
	}

	@Test
	@DisplayName("Multiply negates divide")
	void multiplyNegatesDivide() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element quotient = JNITestUtils.g1Divide(randomElement1, randomElement2);
		final BLS12381Group1Element product = JNITestUtils.g1Multiply(quotient, randomElement2);

		assertNotEquals(null, quotient, "quotient should be valid");
		assertNotEquals(null, product, "product should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product, randomElement1), "multiply should negate divide");
	}

	@Test
	@DisplayName("Divide negates multiply")
	void divideNegatesMultiply() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element product = JNITestUtils.g1Multiply(randomElement1, randomElement2);
		final BLS12381Group1Element quotient = JNITestUtils.g1Divide(product, randomElement2);

		assertNotEquals(null, product, "product should be valid");
		assertNotEquals(null, quotient, "quotient should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(quotient, randomElement1), "divide should negate multiply");
	}

	@Test
	@DisplayName("g1BatchMultiply success")
	void g1BatchMultiplySuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[] {
				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32))
		};

		final BLS12381Group1Element product = JNITestUtils.g1BatchMultiply(elementArray);

		assertNotEquals(null, product, "product should be valid");
		for (final BLS12381Group1Element element : elementArray) {
			assertFalse(BLS12381Group1Bindings.g1ElementEquals(product, element),
					"product shouldn't equal random element");
		}
	}

	@Test
	@DisplayName("g1BatchMultiply compressed")
	void g1BatchMultiplyCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement3 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element randomElement1Compressed = JNITestUtils.g1Compress(randomElement1);
		final BLS12381Group1Element randomElement2Compressed = JNITestUtils.g1Compress(randomElement2);
		final BLS12381Group1Element randomElement3Compressed = JNITestUtils.g1Compress(randomElement3);

		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[] {
				randomElement1, randomElement2, randomElement3
		};

		final BLS12381Group1Element[] elementArrayCompressed = new BLS12381Group1Element[] {
				randomElement1Compressed, randomElement2Compressed, randomElement3Compressed
		};

		final BLS12381Group1Element[] elementArrayMixed = new BLS12381Group1Element[] {
				randomElement1Compressed, randomElement2, randomElement3Compressed
		};

		final BLS12381Group1Element product = JNITestUtils.g1BatchMultiply(elementArray);
		final BLS12381Group1Element productCompressed = JNITestUtils.g1BatchMultiply(elementArrayCompressed);
		final BLS12381Group1Element productMixed = JNITestUtils.g1BatchMultiply(elementArrayMixed);

		assertNotEquals(null, product, "product should be valid");
		assertNotEquals(null, productCompressed, "productCompressed should be valid");
		assertNotEquals(null, productMixed, "productMixed should be valid");

		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product, productCompressed),
				"compression shouldn't affect result");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product, productMixed),
				"compression shouldn't affect result");
	}

	@Test
	@DisplayName("g1BatchMultiply insufficient element count")
	void g1BatchMultiplyInsufficientElements() {
		final Random random = RandomUtils.getRandomPrintSeed();

		// Batch multiplication requires at least 2 elements
		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[] {
				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)) };

		assertNull(JNITestUtils.g1BatchMultiply(elementArray), "not enough elements should result in error");
	}

	@Test
	@DisplayName("g1BatchMultiply with invalid element")
	void g1BatchMultiplyInvalidElement() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[] {
				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
				null };

		assertNull(JNITestUtils.g1BatchMultiply(elementArray), "invalid element in batch should result in error");
	}

	@Test
	@DisplayName("g1BatchMultiply produces the same result every time for identical inputs")
	void g1BatchMultiplyDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[] {
				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32))
		};

		final BLS12381Group1Element product1 = JNITestUtils.g1BatchMultiply(elementArray);
		final BLS12381Group1Element product2 = JNITestUtils.g1BatchMultiply(elementArray);

		assertNotEquals(null, product1, "product1 should be valid");
		assertNotEquals(null, product2, "product2 should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product1, product2),
				"multiplication with same inputs should produce same result");
	}

	@Test
	@DisplayName("g1BatchMultiply produces the same result every time for identical inputs")
	void g1BatchMultiplyCommutative() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group1Element randomElement3 = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element[] elementArray1 = new BLS12381Group1Element[] {
				randomElement2, randomElement3, randomElement1,
		};

		final BLS12381Group1Element[] elementArray2 = new BLS12381Group1Element[] {
				randomElement1, randomElement2, randomElement3
		};

		final BLS12381Group1Element product1 = JNITestUtils.g1BatchMultiply(elementArray1);
		final BLS12381Group1Element product2 = JNITestUtils.g1BatchMultiply(elementArray2);

		assertNotEquals(null, product1, "product1 should be valid");
		assertNotEquals(null, product2, "product2 should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(product1, product2),
				"multiplication with same differently ordered batch inputs should produce same result");
	}

	@Test
	@DisplayName("g1PowZn success")
	void g1PowZnSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element power = JNITestUtils.g1PowZn(
				randomElement, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32)));

		assertNotEquals(null, power, "power should be valid");
		assertFalse(BLS12381Group1Bindings.g1ElementEquals(power, randomElement),
				"power shouldn't equal randomElement");
	}

	@Test
	@DisplayName("g1PowZn compressed")
	void g1PowZnCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element randomElementCompressed = JNITestUtils.g1Compress(randomElement);

		final BLS12381Group1Element power = JNITestUtils.g1PowZn(randomElement, randomScalar);
		final BLS12381Group1Element powerCompressed = JNITestUtils.g1PowZn(randomElementCompressed, randomScalar);

		assertNotEquals(null, power, "power should be valid");
		assertNotEquals(null, powerCompressed, "powerCompressed should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(power, powerCompressed),
				"compression shouldn't affect result");
	}

	@Test
	@DisplayName("Element to the power of 1")
	void g1PowZnOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element power = JNITestUtils.g1PowZn(randomElement, JNITestUtils.getOneScalar());

		assertNotEquals(null, power, "power should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(power, randomElement),
				"element to the power of 1 should equal itself");
	}

	@Test
	@DisplayName("Element to the power of 0")
	void g1PowZnZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element power = JNITestUtils.g1PowZn(
				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
				JNITestUtils.getZeroScalar());

		assertNotEquals(null, power, "power should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(power, JNITestUtils.getG1Identity()),
				"element to the power of 0 should equal identity");
	}

	@Test
	@DisplayName("g1PowZn produces the same result every time for identical inputs")
	void g1PowZnDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element power1 = JNITestUtils.g1PowZn(randomElement, randomScalar);
		final BLS12381Group1Element power2 = JNITestUtils.g1PowZn(randomElement, randomScalar);

		assertNotEquals(null, power1, "power1 should be valid");
		assertNotEquals(null, power2, "power2 should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(power1, power2),
				"power with same inputs should produce same result");
	}

	@Test
	@DisplayName("g1ElementEquals with null arguments returns false")
	void g1ElementEqualsInvalid() {
		final Random random = RandomUtils.getRandomPrintSeed();

		assertFalse(BLS12381Group1Bindings.g1ElementEquals(
						JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)), null),
				"One value being null should return false");
		assertFalse(BLS12381Group1Bindings.g1ElementEquals(
						null, JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32))),
				"One value being null should return false");
	}

	@Test
	@DisplayName("uncompressed g1 elements can be compared with compressed elements")
	void g1EqualsCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element randomElementCompressed = JNITestUtils.g1Compress(randomElement);

		assertNotEquals(null, randomElementCompressed, "randomElementCompressed should be valid");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(randomElement, randomElementCompressed),
				"comparison should work regardless of compression");
		assertTrue(BLS12381Group1Bindings.g1ElementEquals(randomElementCompressed, randomElement),
				"comparison should work regardless of compression");
	}

	@Test
	@DisplayName("compress success")
	void compressSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		assertEquals(96, randomElement.toBytes().length, "uncompressed element should be of length 96");

		final BLS12381Group1Element compressedElement = JNITestUtils.g1Compress(randomElement);

		assertNotEquals(null, compressedElement, "compressedElement should be valid");
		assertEquals(48, compressedElement.toBytes().length, "compressed element should be of length 48");
	}

	@Test
	@DisplayName("checkG1Validity valid")
	void checkG1ValidityValid() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element validCompressedElement = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		validCompressedElement.compress();

		final BLS12381Group1Element validUncompressedElement = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));

		assertTrue(BLS12381Group1Bindings.checkG1Validity(validCompressedElement), "element should be valid");
		assertTrue(BLS12381Group1Bindings.checkG1Validity(validUncompressedElement), "element should be valid");
	}

	@Test
	@DisplayName("checkG1Validity invalid")
	void checkG1ValidityInvalid() {
		final byte[] invalidCompressedElementBytes = new byte[48];
		final byte[] invalidUncompressedElementBytes = new byte[96];

		Arrays.fill(invalidCompressedElementBytes, (byte) 0xFF);
		Arrays.fill(invalidUncompressedElementBytes, (byte) 0xFF);

		final BLS12381Group1Element invalidCompressedElement = new BLS12381Group1Element(
				invalidCompressedElementBytes, new BLS12381Group1());

		final BLS12381Group1Element invalidUncompressedElement = new BLS12381Group1Element(
				invalidUncompressedElementBytes, new BLS12381Group1());

		assertFalse(BLS12381Group1Bindings.checkG1Validity(invalidCompressedElement), "element should be invalid");
		assertFalse(BLS12381Group1Bindings.checkG1Validity(invalidUncompressedElement), "element should be invalid");
	}
}
