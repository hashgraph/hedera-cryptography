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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JNITestUtils {
	/**
	 * Asserts that a JNI call returned a specific error code
	 *
	 * @param callReturn
	 * 		the byte array returned by a JNI call
	 * @param expectedError
	 * 		the expected error code
	 */
	public static void assertErrorFromCall(final byte[] callReturn, final int expectedError) {
		final JNICallResult result = new JNICallResult(callReturn);
		assertEquals(expectedError, result.getErrorCode(), "call didn't return error code [" + expectedError + "]");
	}

	/**
	 * Gets the result of a comparison done through a JNI equality call
	 *
	 * @param callReturn
	 * 		the byte array returned by a JNI call
	 * @return true if the call indicates equality, otherwise false
	 */
	public static boolean getEqualityFromCall(final byte[] callReturn) {
		final JNICallResult result = new JNICallResult(callReturn);
		assertEquals(0, result.getErrorCode(), "call returned error code");

		return result.getResultArray()[0] == 1;
	}

	/**
	 * Gets a scalar from a byte array seed
	 *
	 * @return a scalar from a byte array seed
	 */
	public static BLS12381FieldElement getRandomScalar(final byte[] seed) {
		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		assertEquals(0, BLS12381ScalarBindings.newRandomScalar(seed, output));

		return new BLS12381FieldElement(output, new BLS12381Field());
	}

	/**
	 * Gets a one scalar
	 *
	 * @return a one scalar
	 */
	public static BLS12381FieldElement getOneScalar() {
		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		assertEquals(0, BLS12381ScalarBindings.newOneScalar(output));

		return new BLS12381FieldElement(output, new BLS12381Field());
	}

	/**
	 * Gets a zero scalar
	 *
	 * @return a zero scalar
	 */
	public static BLS12381FieldElement getZeroScalar() {
		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		assertEquals(0, BLS12381ScalarBindings.newZeroScalar(output));

		return new BLS12381FieldElement(output, new BLS12381Field());
	}

	/**
	 * Gets a scalar from an integer
	 *
	 * @return a scalar from an integer
	 */
	public static BLS12381FieldElement getScalarFromInt(final int inputValue) {
		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		assertEquals(0, BLS12381ScalarBindings.newScalarFromInt(inputValue, output));

		return new BLS12381FieldElement(output, new BLS12381Field());
	}

	/**
	 * Computes the sum of 2 scalars. Returns null if an error occurs
	 *
	 * @param element1
	 * 		the first scalar
	 * @param element2
	 * 		the second scalar
	 * @return the sum, or null if an error occurred
	 */
	public static BLS12381FieldElement scalarAdd(
			final BLS12381FieldElement element1,
			final BLS12381FieldElement element2) {

		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		if (BLS12381ScalarBindings.scalarAdd(element1, element2, output) != 0) {
			return null;
		}

		return new BLS12381FieldElement(output, new BLS12381Field());
	}

	/**
	 * Computes the difference of 2 scalars. Returns null if an error occurs
	 *
	 * @param element1
	 * 		the first scalar
	 * @param element2
	 * 		the second scalar
	 * @return the difference, or null if an error occurred
	 */
	public static BLS12381FieldElement scalarSubtract(
			final BLS12381FieldElement element1,
			final BLS12381FieldElement element2) {

		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		if (BLS12381ScalarBindings.scalarSubtract(element1, element2, output) != 0) {
			return null;
		}

		return new BLS12381FieldElement(output, new BLS12381Field());
	}

	/**
	 * Computes the product of 2 scalars. Returns null if an error occurs
	 *
	 * @param element1
	 * 		the first scalar
	 * @param element2
	 * 		the second scalar
	 * @return the product, or null if an error occurred
	 */
	public static BLS12381FieldElement scalarMultiply(
			final BLS12381FieldElement element1,
			final BLS12381FieldElement element2) {

		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		if (BLS12381ScalarBindings.scalarMultiply(element1, element2, output) != 0) {
			return null;
		}

		return new BLS12381FieldElement(output, new BLS12381Field());
	}

	/**
	 * Computes the quotient of 2 scalars. Returns null if an error occurs
	 *
	 * @param element1
	 * 		the first scalar
	 * @param element2
	 * 		the second scalar
	 * @return the quotient, or null if an error occurred
	 */
	public static BLS12381FieldElement scalarDivide(
			final BLS12381FieldElement element1,
			final BLS12381FieldElement element2) {

		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		if (BLS12381ScalarBindings.scalarDivide(element1, element2, output) != 0) {
			return null;
		}

		return new BLS12381FieldElement(output, new BLS12381Field());
	}

	/**
	 * Computes a scalar base the power of a big int
	 *
	 * @param element
	 * 		the scalar base
	 * @param exponent
	 * 		the big int exponent
	 * @return the power, or null if an error occurred
	 */
	public static BLS12381FieldElement scalarPower(
			final BLS12381FieldElement element,
			final byte[] exponent) {

		final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

		if (BLS12381ScalarBindings.scalarPower(element, exponent, output) != 0) {
			return null;
		}

		return new BLS12381FieldElement(output, new BLS12381Field());
	}

	/**
	 * Asserts that a JNI call that returns a boolean returned true
	 *
	 * @param callReturn
	 * 		the byte array returned from the call
	 * @param errorMessage
	 * 		the error to print if the assertion fails
	 */
	public static void assertBooleanCallTrue(final byte[] callReturn, final String errorMessage) {
		assertTrue(getEqualityFromCall(callReturn), errorMessage);
	}

	/**
	 * Asserts that a JNI call that returns a boolean returned false
	 *
	 * @param callReturn
	 * 		the byte array returned from the call
	 * @param errorMessage
	 * 		the error message to print if the assertion fails
	 */
	public static void assertBooleanCallFalse(final byte[] callReturn, final String errorMessage) {
		assertFalse(getEqualityFromCall(callReturn), errorMessage);
	}

	/**
	 * Gets an identity element
	 *
	 * @return an identity element
	 */
	public static BLS12381Group1Element getG1Identity() {
		final byte[] output = new byte[BLS12381Group1.UNCOMPRESSED_SIZE];

		assertEquals(0, BLS12381Group1Bindings.newG1Identity(output));

		return new BLS12381Group1Element(output, new BLS12381Group1());
	}

	/**
	 * Gets a random group element from a byte seed
	 *
	 * @param seed
	 * 		the seed
	 * @return the new group element
	 */
	public static BLS12381Group1Element getG1RandomElement(final byte[] seed) {
		final byte[] output = new byte[BLS12381Group1.UNCOMPRESSED_SIZE];

		assertEquals(0, BLS12381Group1Bindings.newRandomG1(seed, output));

		return new BLS12381Group1Element(output, new BLS12381Group1());
	}

	/**
	 * Compress a group element
	 *
	 * @param element
	 * 		the element to compress
	 * @return the compressed element
	 */
	public static BLS12381Group1Element g1Compress(final BLS12381Group1Element element) {
		final byte[] output = new byte[BLS12381Group1.COMPRESSED_SIZE];

		if (BLS12381Group1Bindings.g1Compress(element, output) != 0) {
			return null;
		}

		return new BLS12381Group1Element(output, new BLS12381Group1());
	}

	/**
	 * Computes the product of 2 group 1 elements. Returns null if an error occurs
	 *
	 * @param element1
	 * 		the first group1 element
	 * @param element2
	 * 		the second group1 element
	 * @return the product, or null if an error occurred
	 */
	public static BLS12381Group1Element g1Multiply(
			final BLS12381Group1Element element1,
			final BLS12381Group1Element element2) {

		final byte[] output = new byte[BLS12381Group1.UNCOMPRESSED_SIZE];

		if (BLS12381Group1Bindings.g1Multiply(element1, element2, output) != 0) {
			return null;
		}

		return new BLS12381Group1Element(output, new BLS12381Group1());
	}

	/**
	 * Computes the quotient of 2 group 1 elements. Returns null if an error occurs
	 *
	 * @param element1
	 * 		the first group1 element
	 * @param element2
	 * 		the second group1 element
	 * @return the quotient, or null if an error occurred
	 */
	public static BLS12381Group1Element g1Divide(
			final BLS12381Group1Element element1,
			final BLS12381Group1Element element2) {

		final byte[] output = new byte[BLS12381Group1.UNCOMPRESSED_SIZE];

		if (BLS12381Group1Bindings.g1Divide(element1, element2, output) != 0) {
			return null;
		}

		return new BLS12381Group1Element(output, new BLS12381Group1());
	}

	/**
	 * Computes the product of a batch of group1 elements. Returns null if an error occurs
	 *
	 * @param elements
	 * 		the batch of elements to get the product of
	 * @return the product, or null if an error occurred
	 */
	public static BLS12381Group1Element g1BatchMultiply(BLS12381Group1Element[] elements) {
		final byte[] output = new byte[BLS12381Group1.UNCOMPRESSED_SIZE];

		if (BLS12381Group1Bindings.g1BatchMultiply(elements, output) != 0) {
			return null;
		}

		return new BLS12381Group1Element(output, new BLS12381Group1());
	}

	/**
	 * Computes a group 1 base to a scalar power
	 *
	 * @param base
	 * 		the group 1 base
	 * @param exponent
	 * 		the scalar exponent
	 * @return the resulting group 1 element, or null if an error occurred
	 */
	public static BLS12381Group1Element g1PowZn(
			final BLS12381Group1Element base,
			final BLS12381FieldElement exponent) {

		final byte[] output = new byte[BLS12381Group1.UNCOMPRESSED_SIZE];

		if (BLS12381Group1Bindings.g1PowZn(base, exponent, output) != 0) {
			return null;
		}

		return new BLS12381Group1Element(output, new BLS12381Group1());
	}

	/**
	 * Gets a group element from the byte array returned from a JNI call
	 *
	 * @param callReturn
	 * 		the byte array returned by a JNI call
	 * @return the group element
	 */
	public static BLS12381Group2Element getG2ElementFromCall(final byte[] callReturn) {
		final JNICallResult result = new JNICallResult(callReturn);
		assertEquals(0, result.getErrorCode(), "call returned error code");

		return new BLS12381Group2Element(result.getResultArray(), new BLS12381Group2());
	}

	/**
	 * Gets an identity element
	 *
	 * @return an identity element
	 */
	public static BLS12381Group2Element getG2Identity() {
		return getG2ElementFromCall(BLS12381Group2Bindings.newG2Identity());
	}

	/**
	 * Gets a random group element from a byte seed
	 *
	 * @param seed
	 * 		the seed
	 * @return the new group element
	 */
	public static BLS12381Group2Element getG2RandomElement(final byte[] seed) {
		return getG2ElementFromCall(BLS12381Group2Bindings.newRandomG2(seed));
	}

	/**
	 * Asserts that two group 2 elements are equal
	 *
	 * @param element1
	 * 		the first element being compared
	 * @param element2
	 * 		the second element being compared
	 * @param errorMessage
	 * 		the error message if the assertion fails
	 */
	public static void assertG2ElementEquals(
			final BLS12381Group2Element element1,
			final BLS12381Group2Element element2,
			final String errorMessage) {

		assertBooleanCallTrue(BLS12381Group2Bindings.g2ElementEquals(element1, element2), errorMessage);
	}

	/**
	 * Asserts that two group 2 elements are not equal
	 *
	 * @param element1
	 * 		the first element being compared
	 * @param element2
	 * 		the second element being compared
	 * @param errorMessage
	 * 		the error message if the assertion fails
	 */
	public static void assertG2ElementNotEquals(
			final BLS12381Group2Element element1,
			final BLS12381Group2Element element2,
			final String errorMessage) {

		assertBooleanCallFalse(BLS12381Group2Bindings.g2ElementEquals(element1, element2), errorMessage);
	}
}
