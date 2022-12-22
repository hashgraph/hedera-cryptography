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

public class JNITestUtils {
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
}
