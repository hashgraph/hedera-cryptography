package com.hedera.platform.bls;

/**
 * Interface representing a cryptographic group element
 */
public interface GroupElement {
    /**
     * Gets the group of the element
     *
     * @return the element's group
     */
    Group getGroup();

    /**
     * Serializes the group elements to a byte array
     *
     * @return the byte array representing the group element
     */
    byte[] toBytes();

    /**
     * Takes the group element to the power of a field element
     *
     * @param exponent the field element exponent
     * @return a new group element which is this group element to the power of a field element
     */
    GroupElement power(final FieldElement exponent);

    /**
     * Multiplies this group element with another
     *
     * @param other the other group element
     * @return a new group element which is the product of this element and another
     */
    GroupElement multiply(final GroupElement other);

    /**
     * Divides this group element by another
     *
     * @param other the other group element
     * @return a new group element which is the quotient of this element and another
     */
    GroupElement divide(final GroupElement other);

    /**
     * Compresses the group element
     *
     * @return this object, compressed
     */
    GroupElement compress();

    /**
     * Gets whether the group element is compressed
     *
     * @return true if the element is compressed, otherwise false
     */
    boolean isCompressed();

    /**
     * {@inheritDoc}
     */
    GroupElement copy();

    /**
     * Checks whether the element bytes are valid
     *
     * @return true of the element bytes are valid, otherwise false
     */
    boolean isValid();
}
