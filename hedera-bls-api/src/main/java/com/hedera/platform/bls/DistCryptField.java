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
	 * @return the new field element
	 * @throws IOException
	 * 		if the input bytes can't be deserialized into a valid element
	 */
	DistCryptFieldElement newElementFromBytes(byte[] bytes) throws IOException;
}
