package com.hedera.platform.bls;

/**
 * Interface representing a generic field
 */
public interface Field {
    /**
     * Creates a new field element from an integer
     *
     * @param i the integer to use to create the field element
     * @return the new field element
     */
    FieldElement elementFromInt(final int i);

    /**
     * Creates a new field element with value 0
     *
     * @return the new field element
     */
    FieldElement zeroElement();

    /**
     * Creates a new field element with value 1
     *
     * @return the new field element
     */
    FieldElement oneElement();

    /**
     * Creates a field element from a seed (256 bits)
     *
     * @param seed a seed to use to generate randomness
     * @return the new field element
     */
    FieldElement randomElement(final byte[] seed);

    /**
     * Creates a field element from its serialized encoding
     *
     * @param bytes serialized form
     * @return the new field element, or null if construction fails
     */
    FieldElement deserializeElementFromBytes(byte[] bytes);

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
