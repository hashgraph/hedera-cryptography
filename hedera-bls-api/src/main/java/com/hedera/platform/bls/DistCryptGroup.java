package com.hedera.platform.bls;

import java.io.IOException;
import java.util.Collection;

public interface DistCryptGroup {
	/**
	 * Creates a new group element with value 1
	 *
	 * @return the new group element
	 */
	DistCryptGroupElement newOneElement();

	/**
	 * Creates a group element from a seed (256 bits)
	 */
	DistCryptGroupElement newElementFromSeed(final byte[] seed);

	/**
	 * Hashes an unbounded length input to a group element
	 *
	 * @param input
	 * 		the input to be hashes
	 * @return the new group element
	 */
	DistCryptGroupElement hashToGroup(final byte[] input);

	/**
	 * Multiplies a collection of group elements together
	 *
	 * @param elements
	 * 		the collection of elements to multiply together
	 * @return a new group element which is the product the collection of elements
	 */
	DistCryptGroupElement batchMultiply(final Collection<DistCryptGroupElement> elements);

	/**
	 * Creates a group element from its serialized encoding
	 *
	 * @param bytes
	 * 		serialized form
	 * @return the new group element
	 * @throws IOException
	 * 		if the input bytes can't be deserialized into a valid element
	 */
	DistCryptGroupElement newElementFromBytes(byte[] bytes) throws IOException;
}
