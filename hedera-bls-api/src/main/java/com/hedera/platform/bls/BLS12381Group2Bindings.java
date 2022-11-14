package com.hedera.platform.bls;

import java.io.IOException;

public final class BLS12381Group2Bindings {
	private BLS12381Group2Bindings() {
	}

	/**
	 * Creates a new identity element of the g2 group
	 *
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing the new group element
	 */
	public static native byte[] newG2Identity();

	/**
	 * Creates a new random element of the g2 group, from a byte array seed
	 *
	 * @param inputSeed
	 * 		the seed to create the new group element with
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing the new group element
	 */
	public static native byte[] newRandomG2(final byte[] inputSeed);

	/**
	 * Checks if 2 elements of the g2 group are equal
	 *
	 * @param element1
	 * 		the first g2 group element
	 * @param element2
	 * 		the second g2 group element
	 * @return a byte array with byte 0 being an error code, and the second byte representing the equality of the input
	 * 		elements. A value of 1 indicates equality, and a value of 0 indicates inequality
	 */
	public static native byte[] g2ElementEquals(
			final BLS12381Group2Element element1,
			final BLS12381Group2Element element2);

	/**
	 * Checks whether a g2 element is valid
	 *
	 * @param element
	 * 		the element being checked for validity
	 * @return a byte array with byte 0 being an error code, and the second byte representing the validity of the input
	 * 		element. A value of 1 indicates a valid element, and a value of 0 indicates an invalid element
	 */
	public static native byte[] checkG2Validity(final BLS12381Group2Element element);

	/**
	 * Computes the quotient of 2 elements of the g2 group
	 *
	 * @param element1
	 * 		the first group element
	 * @param element2
	 * 		the second group element
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing an element of group
	 * 		g2, which is the quotient of the 2 input group elements
	 */
	public static native byte[] g2Divide(final BLS12381Group2Element element1, final BLS12381Group2Element element2);

	/**
	 * Computes the product of 2 elements of the g2 group
	 *
	 * @param element1
	 * 		the first group element
	 * @param element2
	 * 		the second group element
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing an element of group
	 * 		g2, which is the product of the 2 input group elements
	 */
	public static native byte[] g2Multiply(final BLS12381Group2Element element1, final BLS12381Group2Element element2);

	/**
	 * Computes the product of a batch of elements
	 *
	 * @param elementBatch
	 * 		the batch of elements to multiply together
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing an element of group
	 * 		g2, which is the product of a batch of group elements
	 */
	public static native byte[] g2BatchMultiply(final BLS12381Group2Element[] elementBatch);

	/**
	 * Computes the value of a g2 group element, taken to the power of a scalar
	 *
	 * @param base
	 * 		an element of the g2 group
	 * @param exponent
	 * 		the scalar exponent
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing an element of group
	 * 		g2, which is the input group element taken to the power of the input scalar
	 */
	public static native byte[] g2PowZn(final BLS12381Group2Element base, final BLS12381FieldElement exponent);

	/**
	 * Compresses a g2 element
	 *
	 * @param element
	 * 		the element to compress
	 * @return a compressed version of the element
	 */
	public static native byte[] g2Compress(final BLS12381Group2Element element);

	static {
		try {
			new LibraryLoader().loadBundledLibrary(BLS12381Group2Bindings.class);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
