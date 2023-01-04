package com.hedera.platform.bls;

import java.io.IOException;

/**
 * Interface representing a generic field
 */
public interface DistCryptField {
	/**
	 * Creates a new field element from an integer
	 *
	 * @param i
	 * 		the integer to use to create the field element
	 * @return the new field element
	 */
	DistCryptFieldElement newElement(final int i);

	/**
	 * Creates a new field element with value 0
	 *
	 * @return the new field element
	 */
	DistCryptFieldElement newZeroElement();

	/**
	 * Creates a new field element with value 1
	 *
	 * @return the new field element
	 */
	DistCryptFieldElement newOneElement();

	/**
	 * Creates a field element from a seed (256 bits)
	 *
	 * @param seed
	 * 		a seed to use to generate randomness
	 * @return the new field element
	 */
	DistCryptFieldElement newElementFromSeed(final byte[] seed);

	/**
	 * Creates a field element from its serialized encoding
	 *
	 * @param bytes
	 * 		serialized form
	 * @return the new field element, or null if construction fails
	 */
	DistCryptFieldElement newElementFromBytes(byte[] bytes);

	/**
	 * Gets the size in bytes of an element
	 *
	 * @return the size of an element
	 */
	int getElementSize();

	/**
	 * Gets the size in bytes of the seed necessary to generate a new element
	 *
	 * @return the size of a seed needed to generate a new element
	 */
	int getSeedSize();
}
