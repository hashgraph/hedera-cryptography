package com.hedera.platform.bls;

import java.util.ArrayList;
import java.util.List;

import static com.hedera.platform.bls.LibraryLoader.Mode.PREFER_BUNDLED;

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
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing the new scalar
	 */
	public static native byte[] newRandomScalar(final byte[] inputSeed);

	/**
	 * Creates a new scalar from an integer
	 *
	 * @param integer
	 * 		the integer to be used to create the new scalar
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing the new scalar
	 */
	public static native byte[] newScalarFromInt(final int integer);

	/**
	 * Creates a new zero value scalar
	 *
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing the new scalar
	 */
	public static native byte[] newZeroScalar();

	/**
	 * Creates a new one value scalar
	 *
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing the new scalar
	 */
	public static native byte[] newOneScalar();

	/**
	 * Checks whether 2 scalar values are equal
	 *
	 * @param scalar1
	 * 		the first scalar value
	 * @param scalar2
	 * 		the second scalar value
	 * @return a byte array with byte 0 being an error code, and the second byte representing the equality of the input
	 * 		scalars. A value of 1 indicates equality, and a value of 0 indicates inequality
	 */
	public static native byte[] scalarEquals(final BLS12381FieldElement scalar1, final BLS12381FieldElement scalar2);

	/**
	 * Checks whether a scalar is valid
	 *
	 * @param scalar
	 * 		the scalar being checked for validity
	 * @return a byte array with byte 0 being an error code, and the second byte representing the validity of the input
	 * 		scalar. A value of 1 indicates a valid scalar, and a value of 0 indicates an invalid scalar
	 */
	public static native byte[] checkScalarValidity(final BLS12381FieldElement scalar);

	/**
	 * Computes the sum of 2 scalar values
	 *
	 * @param scalar1
	 * 		the first scalar value
	 * @param scalar2
	 * 		the second scalar value
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing a scalar, which is
	 * 		the sum of the 2 input scalars
	 */
	public static native byte[] scalarAdd(final BLS12381FieldElement scalar1, final BLS12381FieldElement scalar2);

	/**
	 * Computes the difference between 2 scalar values
	 *
	 * @param scalar1
	 * 		the first scalar value
	 * @param scalar2
	 * 		the second scalar value
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing a scalar, which is
	 * 		the difference between the 2 input scalars
	 */
	public static native byte[] scalarSubtract(final BLS12381FieldElement scalar1, final BLS12381FieldElement scalar2);

	/**
	 * Computes the product of 2 scalar values
	 *
	 * @param scalar1
	 * 		the first scalar value
	 * @param scalar2
	 * 		the second scalar value
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing a scalar, which is
	 * 		the product of the 2 input scalars
	 */
	public static native byte[] scalarMultiply(final BLS12381FieldElement scalar1, final BLS12381FieldElement scalar2);

	/**
	 * Computes the quotient of 2 scalar values
	 *
	 * @param scalar1
	 * 		the first scalar value
	 * @param scalar2
	 * 		the second scalar value
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing a scalar, which is
	 * 		the quotient of the 2 input scalars
	 */
	public static native byte[] scalarDivide(final BLS12381FieldElement scalar1, final BLS12381FieldElement scalar2);

	/**
	 * Computes the value a scalar to the power of a big integer
	 *
	 * @param base
	 * 		a scalar value
	 * @param exponent
	 * 		a big integer
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing a scalar, which is
	 * 		the result of a scalar value taken to the power of a big integer
	 */
	public static native byte[] scalarPower(final BLS12381FieldElement base, final byte[] exponent);

	static {
		final List<Class> classList = new ArrayList<>();
		classList.add(BLS12381ScalarBindings.class);

		new LibraryLoader(classList).loadLibrary(PREFER_BUNDLED, "pairings_jni_rust");
	}
}
