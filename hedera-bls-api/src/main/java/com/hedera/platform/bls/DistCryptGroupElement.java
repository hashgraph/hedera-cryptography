package com.hedera.platform.bls;

/**
 * Interface representing a cryptographic group element
 */
public interface DistCryptGroupElement {
	/**
	 * Gets the group of the element
	 *
	 * @return the element's group
	 */
	DistCryptGroup getGroup();

	/**
	 * Serializes the group elements to a byte array
	 *
	 * @return the byte array representing the group element
	 */
	byte[] toBytes();

	/**
	 * Takes the group element to the power of a field element
	 *
	 * @param exponent
	 * 		the field element exponent
	 * @return a new group element which is this group element to the power of a field element
	 */
	DistCryptGroupElement power(final DistCryptFieldElement exponent);

	/**
	 * Multiplies this group element with another
	 *
	 * @param other
	 * 		the other group element
	 * @return a new group element which is the product of this element and another
	 */
	DistCryptGroupElement multiply(final DistCryptGroupElement other);

	/**
	 * Divides this group element by another
	 *
	 * @param other
	 * 		the other group element
	 * @return a new group element which is the quotient of this element and another
	 */
	DistCryptGroupElement divide(final DistCryptGroupElement other);

	/**
	 * Compresses the group element
	 *
	 * @return this object, compressed
	 */
	DistCryptGroupElement compress();

	/**
	 * Gets whether the group element is compressed
	 *
	 * @return true if the element is compressed, otherwise false
	 */
	boolean isCompressed();

	/**
	 * {@inheritDoc}
	 */
	@SuppressWarnings("unchecked")
	DistCryptGroupElement copy();
}
