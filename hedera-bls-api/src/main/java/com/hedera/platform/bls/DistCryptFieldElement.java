package com.hedera.platform.bls;

import java.math.BigInteger;

/**
 * An interface representing a generic field element
 */
public interface DistCryptFieldElement {
	/**
	 * Gets the field the element is in
	 *
	 * @return the field
	 */
	DistCryptField getField();

	/**
	 * Serializes the field element to bytes
	 *
	 * @return the byte array representing the element
	 */
	byte[] toBytes();

	/**
	 * Adds another field element to this one
	 *
	 * @param other
	 * 		the other field element
	 * @return a new field element which is the sum of this element and another
	 */
	DistCryptFieldElement add(final DistCryptFieldElement other);

	/**
	 * Subtracts another field element from this one
	 *
	 * @param other
	 * 		the other field element
	 * @return a new field element which is the difference of this element and another
	 */
	DistCryptFieldElement subtract(final DistCryptFieldElement other);

	/**
	 * Multiplies another field element with this one
	 *
	 * @param other
	 * 		the other field element
	 * @return a new field element which is the product of this element and another
	 */
	DistCryptFieldElement multiply(final DistCryptFieldElement other);

	/**
	 * Divides the field element by another
	 *
	 * @param other
	 * 		the other field element
	 * @return a new field element which is the quotient of this element and another
	 */
	DistCryptFieldElement divide(final DistCryptFieldElement other);

	/**
	 * Takes the field element to the power of an integer
	 *
	 * @param e2
	 * 		the exponent integer
	 * @return a new field element which is the power
	 */
	DistCryptFieldElement power(final BigInteger e2);

	/**
	 * Checks whether the element bytes are valid
	 *
	 * @return true of the element bytes are valid, otherwise false
	 */
	boolean isValid();
}
