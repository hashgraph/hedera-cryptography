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

@DisplayName("BLS12_381 Group 1 Bindings Unit Tests")
class BLS12381Group1BindingsTests {

  @Test
  @DisplayName("TEMP")
  void TEMP() {
    //		BLS12381Group1Bindings.newG1Identity();
    //		new SodiumJava(BUNDLED_ONLY);
    BLS12381Group1Bindings.test();
  }
  //
  //	@Test
  //	@DisplayName("newRandomG1 with bad seed returns error code")
  //	void newRandomG1BadSeed() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //
  //	JNITestUtils.assertErrorFromCall(BLS12381Group1Bindings.newRandomG1(RandomUtils.randomByteArray(random, 31)),
  //				3);
  //	}
  //
  //	@Test
  //	@DisplayName("newG1Identity produces the same result every time")
  //	void newG1IdentityDeterministic() {
  //		JNITestUtils.assertG1ElementEquals(JNITestUtils.getG1Identity(), JNITestUtils.getG1Identity(),
  //				"identity should equal identity");
  //	}
  //
  //	@Test
  //	@DisplayName("g1Divide success")
  //	void g1DivideSuccess() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element quotient = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Divide(randomElement1, randomElement2));
  //
  //		JNITestUtils.assertG1ElementNotEquals(quotient, randomElement1, "quotient shouldn't equal
  // randomElement1");
  //		JNITestUtils.assertG1ElementNotEquals(quotient, randomElement2, "quotient shouldn't equal
  // randomElement2");
  //	}
  //
  //	@Test
  //	@DisplayName("g1Divide compressed")
  //	void g1DivideCompressed() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element randomElement1Compressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Compress(randomElement1));
  //		final BLS12381Group1Element randomElement2Compressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Compress(randomElement2));
  //
  //		final BLS12381Group1Element quotient = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Divide(randomElement1, randomElement2));
  //		final BLS12381Group1Element quotientCompressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Divide(randomElement1Compressed, randomElement2Compressed));
  //
  //		JNITestUtils.assertG1ElementEquals(quotient, quotientCompressed, "compression shouldn't affect
  // result");
  //	}
  //
  //	@Test
  //	@DisplayName("g1Divide with null arguments throws error")
  //	void g1DivideFailure() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		JNITestUtils.assertErrorFromCall(BLS12381Group1Bindings.g1Divide(
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)), null), 1);
  //		JNITestUtils.assertErrorFromCall(BLS12381Group1Bindings.g1Divide(
  //				null, JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32))), 1);
  //	}
  //
  //	@Test
  //	@DisplayName("Dividing by identity doesn't change element")
  //	void g1DivideByIdentity() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		JNITestUtils.assertG1ElementEquals(
  //				JNITestUtils.getG1ElementFromCall(
  //						BLS12381Group1Bindings.g1Divide(randomElement, JNITestUtils.getG1Identity())),
  //				randomElement,
  //				"dividing by identity shouldn't have an effect");
  //	}
  //
  //	@Test
  //	@DisplayName("g1Divide produces the same result every time for identical inputs")
  //	void g1DivideDeterministic() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		JNITestUtils.assertG1ElementEquals(
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1Divide(randomElement1,
  // randomElement2)),
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1Divide(randomElement1,
  // randomElement2)),
  //				"division with same inputs should produce same result");
  //	}
  //
  //	@Test
  //	@DisplayName("g1Multiply success")
  //	void g1MultiplySuccess() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element product = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Multiply(randomElement1, randomElement2));
  //
  //		JNITestUtils.assertG1ElementNotEquals(product, randomElement1, "product shouldn't equal
  // randomElement1");
  //		JNITestUtils.assertG1ElementNotEquals(product, randomElement2, "product shouldn't equal
  // randomElement2");
  //	}
  //
  //	@Test
  //	@DisplayName("g1Multiply compressed")
  //	void g1MultiplyCompressed() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element randomElement1Compressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Compress(randomElement1));
  //		final BLS12381Group1Element randomElement2Compressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Compress(randomElement2));
  //
  //		final BLS12381Group1Element product = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Multiply(randomElement1, randomElement2));
  //		final BLS12381Group1Element productCompressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Multiply(randomElement1Compressed, randomElement2Compressed));
  //
  //		JNITestUtils.assertG1ElementEquals(product, productCompressed, "compression shouldn't affect
  // result");
  //	}
  //
  //	@Test
  //	@DisplayName("g1Multiply with null arguments throws error")
  //	void g1MultiplyFailure() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		JNITestUtils.assertErrorFromCall(BLS12381Group1Bindings.g1Multiply(
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)), null), 1);
  //		JNITestUtils.assertErrorFromCall(BLS12381Group1Bindings.g1Multiply(
  //				null, JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32))), 1);
  //	}
  //
  //	@Test
  //	@DisplayName("Multiplying by identity doesn't change element")
  //	void g1MultiplyByIdentity() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		JNITestUtils.assertG1ElementEquals(
  //				JNITestUtils.getG1ElementFromCall(
  //						BLS12381Group1Bindings.g1Multiply(randomElement, JNITestUtils.getG1Identity())),
  //				randomElement,
  //				"multiplying by identity shouldn't have an effect");
  //	}
  //
  //	@Test
  //	@DisplayName("g1Multiply produces the same result every time for identical inputs")
  //	void g1MultiplyDeterministic() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		JNITestUtils.assertG1ElementEquals(
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1Multiply(randomElement1,
  // randomElement2)),
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1Multiply(randomElement1,
  // randomElement2)),
  //				"multiplication with same inputs should produce same result");
  //	}
  //
  //	@Test
  //	@DisplayName("Multiply negates divide")
  //	void multiplyNegatesDivide() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element quotient = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Divide(randomElement1, randomElement2));
  //
  //		JNITestUtils.assertG1ElementEquals(
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1Multiply(quotient,
  // randomElement2)),
  //				randomElement1,
  //				"multiply should negate divide");
  //	}
  //
  //	@Test
  //	@DisplayName("Divide negates multiply")
  //	void divideNegatesMultiply() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element product = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Multiply(randomElement1, randomElement2));
  //
  //		JNITestUtils.assertG1ElementEquals(
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1Divide(product, randomElement2)),
  //				randomElement1,
  //				"divide should negate multiply");
  //	}
  //
  //	@Test
  //	@DisplayName("g1BatchMultiply success")
  //	void g1BatchMultiplySuccess() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[] {
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32))
  //		};
  //
  //		final BLS12381Group1Element product =
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1BatchMultiply(elementArray));
  //
  //		for (final BLS12381Group1Element element : elementArray) {
  //			JNITestUtils.assertG1ElementNotEquals(product, element, "product shouldn't equal random
  // element");
  //		}
  //	}
  //
  //	@Test
  //	@DisplayName("g1BatchMultiply compressed")
  //	void g1BatchMultiplyCompressed() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement1 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381Group1Element randomElement2 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381Group1Element randomElement3 = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element randomElement1Compressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Compress(randomElement1));
  //		final BLS12381Group1Element randomElement2Compressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Compress(randomElement2));
  //		final BLS12381Group1Element randomElement3Compressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Compress(randomElement3));
  //
  //		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[] {
  //				randomElement1, randomElement2, randomElement3
  //		};
  //
  //		final BLS12381Group1Element[] elementArrayCompressed = new BLS12381Group1Element[] {
  //				randomElement1Compressed, randomElement2Compressed, randomElement3Compressed
  //		};
  //
  //		final BLS12381Group1Element product =
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1BatchMultiply(elementArray));
  //		final BLS12381Group1Element productCompressed =
  //
  //	JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1BatchMultiply(elementArrayCompressed));
  //
  //		JNITestUtils.assertG1ElementEquals(product, productCompressed, "compression shouldn't affect
  // result");
  //	}
  //
  //	@Test
  //	@DisplayName("g1BatchMultiply insufficient element count")
  //	void g1BatchMultiplyInsufficientElements() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		// Batch multiplication requires at least 2 elements
  //		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[] {
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)) };
  //
  //		JNITestUtils.assertErrorFromCall(BLS12381Group1Bindings.g1BatchMultiply(elementArray), 7);
  //	}
  //
  //	@Test
  //	@DisplayName("g1BatchMultiply with invalid element")
  //	void g1BatchMultiplyInvalidElement() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[] {
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)), null };
  //
  //		JNITestUtils.assertErrorFromCall(BLS12381Group1Bindings.g1BatchMultiply(elementArray), 1);
  //	}
  //
  //	@Test
  //	@DisplayName("g1BatchMultiply produces the same result every time for identical inputs")
  //	void g1BatchMultiplyDeterministic() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[] {
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32))
  //		};
  //
  //		JNITestUtils.assertG1ElementEquals(
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1BatchMultiply(elementArray)),
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1BatchMultiply(elementArray)),
  //				"multiplication with same inputs should produce same result");
  //	}
  //
  //	@Test
  //	@DisplayName("g1PowZn success")
  //	void g1PowZnSuccess() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element power = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1PowZn(randomElement,
  //						JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32))));
  //
  //		JNITestUtils.assertG1ElementNotEquals(power, randomElement, "power shouldn't equal
  // randomElement");
  //	}
  //
  //	@Test
  //	@DisplayName("g1PowZn compressed")
  //	void g1PowZnCompressed() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381FieldElement randomScalar =
  // JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element randomElementCompressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Compress(randomElement));
  //
  //		final BLS12381Group1Element power = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1PowZn(randomElement, randomScalar));
  //		final BLS12381Group1Element powerCompressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1PowZn(randomElementCompressed, randomScalar));
  //
  //		JNITestUtils.assertG1ElementEquals(power, powerCompressed, "compression shouldn't affect
  // result");
  //	}
  //
  //	@Test
  //	@DisplayName("Element to the power of 1")
  //	void g1PowZnOne() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element power = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1PowZn(randomElement, JNITestUtils.getOneScalar()));
  //
  //		JNITestUtils.assertG1ElementEquals(power, randomElement, "element to the power of 1 should
  // equal itself");
  //	}
  //
  //	@Test
  //	@DisplayName("Element to the power of 0")
  //	void g1PowZnZero() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element power = JNITestUtils.getG1ElementFromCall(
  //
  //	BLS12381Group1Bindings.g1PowZn(JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)),
  //						JNITestUtils.getZeroScalar()));
  //
  //		JNITestUtils.assertG1ElementEquals(power, JNITestUtils.getG1Identity(),
  //				"element to the power of 0 should equal identity");
  //	}
  //
  //	@Test
  //	@DisplayName("g1PowZn produces the same result every time for identical inputs")
  //	void g1PowZnDeterministic() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		final BLS12381FieldElement randomScalar =
  // JNITestUtils.getRandomScalar(RandomUtils.randomByteArray(random, 32));
  //
  //		JNITestUtils.assertG1ElementEquals(
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1PowZn(randomElement,
  // randomScalar)),
  //				JNITestUtils.getG1ElementFromCall(BLS12381Group1Bindings.g1PowZn(randomElement,
  // randomScalar)),
  //				"power with same inputs should produce same result");
  //	}
  //
  //	@Test
  //	@DisplayName("g1ElementEquals with null arguments throws error")
  //	void g1ElementEqualsFailure() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		JNITestUtils.assertErrorFromCall(BLS12381Group1Bindings.g1ElementEquals(
  //				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)), null), 1);
  //		JNITestUtils.assertErrorFromCall(BLS12381Group1Bindings.g1ElementEquals(
  //				null, JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32))), 1);
  //	}
  //
  //	@Test
  //	@DisplayName("uncompressed g1 elements can be compared with compressed elements")
  //	void g1EqualsCompressed() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		final BLS12381Group1Element randomElementCompressed = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Compress(randomElement));
  //
  //		JNITestUtils.assertG1ElementEquals(randomElement, randomElementCompressed,
  //				"comparison should work regardless of compression");
  //		JNITestUtils.assertG1ElementEquals(randomElementCompressed, randomElement,
  //				"comparison should work regardless of compression");
  //	}
  //
  //	@Test
  //	@DisplayName("compress success")
  //	void compressSuccess() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element randomElement = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //		assertEquals(96, randomElement.toBytes().length, "uncompressed element should be of length
  // 96");
  //
  //		final BLS12381Group1Element compressedElement = JNITestUtils.getG1ElementFromCall(
  //				BLS12381Group1Bindings.g1Compress(randomElement));
  //
  //		assertEquals(48, compressedElement.toBytes().length, "compressed element should be of length
  // 48");
  //	}
  //
  //	@Test
  //	@DisplayName("checkG1Validity valid")
  //	void checkG1ValidityValid() {
  //		final Random random = RandomUtils.getRandomPrintSeed();
  //
  //		final BLS12381Group1Element validCompressedElement = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //		validCompressedElement.compress();
  //
  //		final BLS12381Group1Element validUncompressedElement = JNITestUtils.getG1RandomElement(
  //				RandomUtils.randomByteArray(random, 32));
  //
  //
  //	JNITestUtils.assertBooleanCallTrue(BLS12381Group1Bindings.checkG1Validity(validCompressedElement),
  //				"element should be valid");
  //
  //	JNITestUtils.assertBooleanCallTrue(BLS12381Group1Bindings.checkG1Validity(validUncompressedElement),
  //				"element should be valid");
  //	}
  //
  //	@Test
  //	@DisplayName("checkG1Validity invalid")
  //	void checkG1ValidityInvalid() {
  //		final byte[] invalidCompressedElementBytes = new byte[48];
  //		final byte[] invalidUncompressedElementBytes = new byte[96];
  //
  //		Arrays.fill(invalidCompressedElementBytes, (byte) 0xFF);
  //		Arrays.fill(invalidUncompressedElementBytes, (byte) 0xFF);
  //
  //		final BLS12381Group1Element invalidCompressedElement = new BLS12381Group1Element(
  //				invalidCompressedElementBytes, new BLS12381Group1());
  //
  //		final BLS12381Group1Element invalidUncompressedElement = new BLS12381Group1Element(
  //				invalidUncompressedElementBytes, new BLS12381Group1());
  //
  //
  //	JNITestUtils.assertBooleanCallFalse(BLS12381Group1Bindings.checkG1Validity(invalidCompressedElement),
  //				"element should be invalid");
  //
  //	JNITestUtils.assertBooleanCallFalse(BLS12381Group1Bindings.checkG1Validity(invalidUncompressedElement),
  //				"element should be invalid");
  //	}
}
