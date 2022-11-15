package com.hedera.platform.bls;

import java.io.IOException;

/**
 * An interface class to allow java access to functions in the rust library BLS12_381
 * <p>
 * Byte arrays returned by the native functions begin with a byte representing an error code. If this error code is
 * 0, the remaining bytes in the array will contain the function result. If the error code is anything other than 0, the
 * array will not have any other bytes
 */
public final class BLS12381ScalarBindings {
	private BLS12381ScalarBindings() {
	}

	/**
	 * Creates a new random scalar from a seed value
	 *
	 * @param inputSeed
	 * 		the byte seed to be used to create the new scalar
	 * @param output
	 * 		the byte array that will be filled with the new scalar
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int newRandomScalar(final byte[] inputSeed, final byte[] output);

	/**
	 * Creates a new scalar from an integer
	 *
	 * @param integer
	 * 		the integer to be used to create the new scalar
	 * @param output
	 * 		the byte array that will be filled with the new scalar
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int newScalarFromInt(final int integer, final byte[] output);

	/**
	 * Creates a new zero value scalar
	 *
	 * @param output
	 * 		the byte array that will be filled with the new scalar
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int newZeroScalar(final byte[] output);

	/**
	 * Creates a new one value scalar
	 *
	 * @param output
	 * 		the byte array that will be filled with the new scalar
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int newOneScalar(final byte[] output);

	/**
	 * Checks whether 2 scalar values are equal
	 *
	 * @param scalar1
	 * 		the first scalar value
	 * @param scalar2
	 * 		the second scalar value
	 * @return true if the scalars are equal, otherwise false
	 */
	public static native boolean scalarEquals(final BLS12381FieldElement scalar1, final BLS12381FieldElement scalar2);

	/**
	 * Checks whether a scalar is valid
	 *
	 * @param scalar
	 * 		the scalar being checked for validity
	 * @return true if the scalar is valid, otherwise false
	 */
	public static native boolean checkScalarValidity(final BLS12381FieldElement scalar);

	/**
	 * Computes the sum of 2 scalar values
	 *
	 * @param scalar1
	 * 		the first scalar value
	 * @param scalar2
	 * 		the second scalar value
	 * @param output
	 * 		the byte array that will be filled with the new scalar
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int scalarAdd(final BLS12381FieldElement scalar1, final BLS12381FieldElement scalar2,
			final byte[] output);

	/**
	 * Computes the difference between 2 scalar values
	 *
	 * @param scalar1
	 * 		the first scalar value
	 * @param scalar2
	 * 		the second scalar value
	 * @param output
	 * 		the byte array that will be filled with the new scalar
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int scalarSubtract(final BLS12381FieldElement scalar1, final BLS12381FieldElement scalar2,
			final byte[] output);

	/**
	 * Computes the product of 2 scalar values
	 *
	 * @param scalar1
	 * 		the first scalar value
	 * @param scalar2
	 * 		the second scalar value
	 * @param output
	 * 		the byte array that will be filled with the new scalar
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int scalarMultiply(final BLS12381FieldElement scalar1, final BLS12381FieldElement scalar2,
			final byte[] output);

	/**
	 * Computes the quotient of 2 scalar values
	 *
	 * @param scalar1
	 * 		the first scalar value
	 * @param scalar2
	 * 		the second scalar value
	 * @param output
	 * 		the byte array that will be filled with the new scalar
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int scalarDivide(final BLS12381FieldElement scalar1, final BLS12381FieldElement scalar2,
			final byte[] output);

	/**
	 * Computes the value a scalar to the power of a big integer
	 *
	 * @param base
	 * 		a scalar value
	 * @param exponent
	 * 		a big integer
	 * @param output
	 * 		the byte array that will be filled with the new scalar
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int scalarPower(final BLS12381FieldElement base, final byte[] exponent, final byte[] output);

	static {
		try {
			new LibraryLoader().loadBundledLibrary(BLS12381ScalarBindings.class);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
