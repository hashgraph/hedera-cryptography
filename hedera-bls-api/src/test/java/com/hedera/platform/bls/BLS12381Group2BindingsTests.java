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

@DisplayName("BLS12_381 Group 2 Bindings Unit Tests")
class BLS12381Group2BindingsTests {
	@Test
	@DisplayName("newRandomG2 with unique seeds produces unique results")
	void newRandomG2Unique() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement1 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement2 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertG2ElementNotEquals(randomElement1, randomElement2, "random elements shouldn't be equal");

		JNITestUtils.assertG2ElementNotEquals(randomElement1, JNITestUtils.getG2Identity(),
				"random element shouldn't equal identity");
		JNITestUtils.assertG2ElementNotEquals(randomElement2, JNITestUtils.getG2Identity(),
				"random element shouldn't equal identity");
	}

	@Test
	@DisplayName("newRandomG2 from same seed are equal")
	void newRandomG2Deterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final byte[] seed = RandomUtils.randomByteArray(random, 32);

		JNITestUtils.assertG2ElementEquals(
				JNITestUtils.getG2RandomElement(seed),
				JNITestUtils.getG2RandomElement(seed),
				"elements from the same seed should be equal");
	}

	@Test
	@DisplayName("newRandomG2 with bad seed returns error code")
	void newRandomG2BadSeed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381Group2Bindings.newRandomG2(RandomUtils.randomByteArray(random, 31)),
				3);
	}

	@Test
	@DisplayName("newG2Identity produces the same result every time")
	void newG2IdentityDeterministic() {
		JNITestUtils.assertG2ElementEquals(JNITestUtils.getG2Identity(), JNITestUtils.getG2Identity(),
				"identity should equal identity");
	}

	@Test
	@DisplayName("g2Divide success")
	void g2DivideSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement1 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement2 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element quotient = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Divide(randomElement1, randomElement2));

		JNITestUtils.assertG2ElementNotEquals(quotient, randomElement1, "quotient shouldn't equal randomElement1");
		JNITestUtils.assertG2ElementNotEquals(quotient, randomElement2, "quotient shouldn't equal randomElement2");
	}

	@Test
	@DisplayName("g2Divide compressed")
	void g2DivideCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement1 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement2 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element randomElement1Compressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(randomElement1));
		final BLS12381Group2Element randomElement2Compressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(randomElement2));

		final BLS12381Group2Element quotient = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Divide(randomElement1, randomElement2));
		final BLS12381Group2Element quotientCompressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Divide(randomElement1Compressed, randomElement2Compressed));

		JNITestUtils.assertG2ElementEquals(quotient, quotientCompressed, "compression shouldn't affect result");
	}

	@Test
	@DisplayName("g2Divide with null arguments throws error")
	void g2DivideFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381Group2Bindings.g2Divide(
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32)), null), 1);
		JNITestUtils.assertErrorFromCall(BLS12381Group2Bindings.g2Divide(
				null, JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32))), 1);
	}

	@Test
	@DisplayName("Dividing by identity doesn't change element")
	void g2DivideByIdentity() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertG2ElementEquals(
				JNITestUtils.getG2ElementFromCall(
						BLS12381Group2Bindings.g2Divide(randomElement, JNITestUtils.getG2Identity())),
				randomElement,
				"dividing by identity shouldn't have an effect");
	}

	@Test
	@DisplayName("g2Divide produces the same result every time for identical inputs")
	void g2DivideDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement1 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement2 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertG2ElementEquals(
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2Divide(randomElement1, randomElement2)),
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2Divide(randomElement1, randomElement2)),
				"division with same inputs should produce same result");
	}

	@Test
	@DisplayName("g2Multiply success")
	void g2MultiplySuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement1 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement2 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element product = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Multiply(randomElement1, randomElement2));

		JNITestUtils.assertG2ElementNotEquals(product, randomElement1, "product shouldn't equal randomElement1");
		JNITestUtils.assertG2ElementNotEquals(product, randomElement2, "product shouldn't equal randomElement2");
	}

	@Test
	@DisplayName("g2Multiply compressed")
	void g2MultiplyCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement1 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement2 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element randomElement1Compressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(randomElement1));
		final BLS12381Group2Element randomElement2Compressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(randomElement2));

		final BLS12381Group2Element product = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Multiply(randomElement1, randomElement2));
		final BLS12381Group2Element productCompressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Multiply(randomElement1Compressed, randomElement2Compressed));

		JNITestUtils.assertG2ElementEquals(product, productCompressed, "compression shouldn't affect result");
	}

	@Test
	@DisplayName("g2Multiply with null arguments throws error")
	void g2MultiplyFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381Group2Bindings.g2Multiply(
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32)), null), 1);
		JNITestUtils.assertErrorFromCall(BLS12381Group2Bindings.g2Multiply(
				null, JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32))), 1);
	}

	@Test
	@DisplayName("Multiplying by identity doesn't change element")
	void g2MultiplyByIdentity() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertG2ElementEquals(
				JNITestUtils.getG2ElementFromCall(
						BLS12381Group2Bindings.g2Multiply(randomElement, JNITestUtils.getG2Identity())),
				randomElement,
				"multiplying by identity shouldn't have an effect");
	}

	@Test
	@DisplayName("g2Multiply produces the same result every time for identical inputs")
	void g2MultiplyDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement1 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement2 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertG2ElementEquals(
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2Multiply(randomElement1, randomElement2)),
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2Multiply(randomElement1, randomElement2)),
				"multiplication with same inputs should produce same result");
	}

	@Test
	@DisplayName("Multiply negates divide")
	void multiplyNegatesDivide() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement1 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement2 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element quotient = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Divide(randomElement1, randomElement2));

		JNITestUtils.assertG2ElementEquals(
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2Multiply(quotient, randomElement2)),
				randomElement1,
				"multiply should negate divide");
	}

	@Test
	@DisplayName("Divide negates multiply")
	void divideNegatesMultiply() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement1 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement2 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element product = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Multiply(randomElement1, randomElement2));

		JNITestUtils.assertG2ElementEquals(
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2Divide(product, randomElement2)),
				randomElement1,
				"divide should negate multiply");
	}

	@Test
	@DisplayName("g2BatchMultiply success")
	void g2BatchMultiplySuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element[] elementArray = new BLS12381Group2Element[] {
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32)),
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32)),
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32))
		};

		final BLS12381Group2Element product =
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2BatchMultiply(elementArray));

		for (final BLS12381Group2Element element : elementArray) {
			JNITestUtils.assertG2ElementNotEquals(product, element, "product shouldn't equal random element");
		}
	}

	@Test
	@DisplayName("g2BatchMultiply compressed")
	void g2BatchMultiplyCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement1 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement2 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element randomElement3 = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element randomElement1Compressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(randomElement1));
		final BLS12381Group2Element randomElement2Compressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(randomElement2));
		final BLS12381Group2Element randomElement3Compressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(randomElement3));

		final BLS12381Group2Element[] elementArray = new BLS12381Group2Element[] {
				randomElement1, randomElement2, randomElement3
		};

		final BLS12381Group2Element[] elementArrayCompressed = new BLS12381Group2Element[] {
				randomElement1Compressed, randomElement2Compressed, randomElement3Compressed
		};

		final BLS12381Group2Element product =
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2BatchMultiply(elementArray));
		final BLS12381Group2Element productCompressed =
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2BatchMultiply(elementArrayCompressed));

		JNITestUtils.assertG2ElementEquals(product, productCompressed, "compression shouldn't affect result");
	}

	@Test
	@DisplayName("g2BatchMultiply insufficient element count")
	void g2BatchMultiplyInsufficientElements() {
		final Random random = RandomUtils.getRandomPrintSeed();

		// Batch multiplication requires at least 2 elements
		final BLS12381Group2Element[] elementArray = new BLS12381Group2Element[] {
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32)) };

		JNITestUtils.assertErrorFromCall(BLS12381Group2Bindings.g2BatchMultiply(elementArray), 7);
	}

	@Test
	@DisplayName("g2BatchMultiply with invalid element")
	void g2BatchMultiplyInvalidElement() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element[] elementArray = new BLS12381Group2Element[] {
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32)), null };

		JNITestUtils.assertErrorFromCall(BLS12381Group2Bindings.g2BatchMultiply(elementArray), 1);
	}

	@Test
	@DisplayName("g2BatchMultiply produces the same result every time for identical inputs")
	void g2BatchMultiplyDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element[] elementArray = new BLS12381Group2Element[] {
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32)),
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32)),
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32))
		};

		JNITestUtils.assertG2ElementEquals(
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2BatchMultiply(elementArray)),
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2BatchMultiply(elementArray)),
				"multiplication with same inputs should produce same result");
	}

	@Test
	@DisplayName("g2PowZn success")
	void g2PowZnSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element power = JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2PowZn(
				randomElement, JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))));

		JNITestUtils.assertG2ElementNotEquals(power, randomElement, "power shouldn't equal randomElement");
	}

	@Test
	@DisplayName("g2PowZn compressed")
	void g2PowZnCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element randomElementCompressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(randomElement));

		final BLS12381Group2Element power = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2PowZn(randomElement, randomScalar));
		final BLS12381Group2Element powerCompressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2PowZn(randomElementCompressed, randomScalar));

		JNITestUtils.assertG2ElementEquals(power, powerCompressed, "compression shouldn't affect result");
	}

	@Test
	@DisplayName("Element to the power of 1")
	void g2PowZnOne() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element power = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2PowZn(randomElement, JNITestUtils.getOneScalar()));

		JNITestUtils.assertG2ElementEquals(power, randomElement, "element to the power of 1 should equal itself");
	}

	@Test
	@DisplayName("Element to the power of 0")
	void g2PowZnZero() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element power = JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2PowZn(
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32)),
				JNITestUtils.getZeroScalar()));

		JNITestUtils.assertG2ElementEquals(power, JNITestUtils.getG2Identity(),
				"element to the power of 0 should equal identity");
	}

	@Test
	@DisplayName("g2PowZn produces the same result every time for identical inputs")
	void g2PowZnDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381FieldElement randomScalar = JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertG2ElementEquals(
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2PowZn(randomElement, randomScalar)),
				JNITestUtils.getG2ElementFromCall(BLS12381Group2Bindings.g2PowZn(randomElement, randomScalar)),
				"power with same inputs should produce same result");
	}

	@Test
	@DisplayName("g2ElementEquals with null arguments throws error")
	void g2ElementEqualsFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381Group2Bindings.g2ElementEquals(
				JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32)), null), 1);
		JNITestUtils.assertErrorFromCall(BLS12381Group2Bindings.g2ElementEquals(
				null, JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32))), 1);
	}

	@Test
	@DisplayName("uncompressed g2 elements can be compared with compressed elements")
	void g2EqualsCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group2Element randomElementCompressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(randomElement));

		JNITestUtils.assertG2ElementEquals(randomElement, randomElementCompressed,
				"comparison should work regardless of compression");
		JNITestUtils.assertG2ElementEquals(randomElementCompressed, randomElement,
				"comparison should work regardless of compression");
	}

	@Test
	@DisplayName("compress success")
	void compressSuccess() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element randomElement = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		assertEquals(192, randomElement.toBytes().length, "uncompressed element should be of length 96");

		final BLS12381Group2Element compressedElement = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(randomElement));

		assertEquals(96, compressedElement.toBytes().length, "compressed element should be of length 48");
	}

	@Test
	@DisplayName("checkG2Validity valid")
	void checkG2ValidityValid() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group2Element validCompressedElement = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));
		validCompressedElement.compress();

		final BLS12381Group2Element validUncompressedElement = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertBooleanCallTrue(BLS12381Group2Bindings.checkG2Validity(validCompressedElement),
				"element should be valid");
		JNITestUtils.assertBooleanCallTrue(BLS12381Group2Bindings.checkG2Validity(validUncompressedElement),
				"element should be valid");
	}

	@Test
	@DisplayName("checkG2Validity invalid")
	void checkG2ValidityInvalid() {
		final byte[] invalidCompressedElementBytes = new byte[96];
		final byte[] invalidUncompressedElementBytes = new byte[192];

		Arrays.fill(invalidCompressedElementBytes, (byte) 0xFF);
		Arrays.fill(invalidUncompressedElementBytes, (byte) 0xFF);

		final BLS12381Group2Element invalidCompressedElement = new BLS12381Group2Element(
				invalidCompressedElementBytes, new BLS12381Group2());

		final BLS12381Group2Element invalidUncompressedElement = new BLS12381Group2Element(
				invalidUncompressedElementBytes, new BLS12381Group2());

		JNITestUtils.assertBooleanCallFalse(BLS12381Group2Bindings.checkG2Validity(invalidCompressedElement),
				"element should be invalid");
		JNITestUtils.assertBooleanCallFalse(BLS12381Group2Bindings.checkG2Validity(invalidUncompressedElement),
				"element should be invalid");
	}
}
