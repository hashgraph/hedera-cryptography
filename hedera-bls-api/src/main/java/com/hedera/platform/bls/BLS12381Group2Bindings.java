package com.hedera.platform.bls;

import java.io.IOException;

/**
 * Class containing definitions for native rust functions that operate on the g2 group
 */
public final class BLS12381Group2Bindings {
	/**
	 * Hidden constructor
	 */
	private BLS12381Group2Bindings() {
	}

	/**
	 * Creates a new identity element of the g2 group
	 *
	 * @param output the byte array that will be filled with the new group element
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int newG2Identity(final byte[] output);

	/**
	 * Creates a new random element of the g2 group, from a byte array seed
	 *
	 * @param inputSeed the seed to create the new group element with
	 * @param output    the byte array that will be filled with the new group element
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int newRandomG2(final byte[] inputSeed, final byte[] output);

	/**
	 * Checks if 2 elements of the g2 group are equal
	 *
	 * @param element1 the first g2 group element
	 * @param element2 the second g2 group element
	 * @return true if the elements are equal, otherwise false
	 */
	public static native boolean g2ElementEquals(
			final BLS12381Group2Element element1, final BLS12381Group2Element element2);

	/**
	 * Checks whether a g2 element is valid
	 *
	 * @param element the element being checked for validity
	 * @return true if the element is valid, otherwise false
	 */
	public static native boolean checkG2Validity(final BLS12381Group2Element element);

	/**
	 * Computes the quotient of 2 elements of the g2 group
	 *
	 * @param element1 the first group element
	 * @param element2 the second group element
	 * @param output   the byte array that will be filled with the quotient group element
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int g2Divide(
			final BLS12381Group2Element element1, final BLS12381Group2Element element2,
			final byte[] output);

	/**
	 * Computes the product of 2 elements of the g2 group
	 *
	 * @param element1 the first group element
	 * @param element2 the second group element
	 * @param output   the byte array that will be filled with the product group element
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int g2Multiply(
			final BLS12381Group2Element element1, final BLS12381Group2Element element2,
			final byte[] output);

	/**
	 * Computes the product of a batch of elements
	 *
	 * @param elementBatch the batch of elements to multiply together
	 * @param output       the byte array that will be filled with the product group element
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int g2BatchMultiply(final BLS12381Group2Element[] elementBatch, final byte[] output);

	/**
	 * Computes the value of a g2 group element, taken to the power of a scalar
	 *
	 * @param base     an element of the g2 group
	 * @param exponent the scalar exponent
	 * @param output   the byte array that will be filled with the new result group element
	 * @return a non-zero error code if there was an error, otherwise 0
	 */
	public static native int g2PowZn(final BLS12381Group2Element base, final BLS12381FieldElement exponent,
									 final byte[] output);

	/**
	 * Compresses a g2 element
	 *
	 * @param element the element to compress
	 * @param output  the byte array that will be filled with the compressed group element
	 * @return a compressed version of the element
	 */
	public static native int g2Compress(final BLS12381Group2Element element, final byte[] output);

	static {
		try {
			new LibraryLoader().loadBundledLibrary(BLS12381Group2Bindings.class);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
