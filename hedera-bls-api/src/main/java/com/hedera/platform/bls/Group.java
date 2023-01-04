package com.hedera.platform.bls;

import java.util.Collection;

public interface Group {
    /**
     * Creates a new group element with value 1
     *
     * @return the new group element
     */
    GroupElement newOneElement();

    /**
     * Creates a group element from a seed (256 bits)
     */
    GroupElement newElementFromSeed(final byte[] seed);

    /**
     * Hashes an unbounded length input to a group element
     *
     * @param input the input to be hashes
     * @return the new group element
     */
    GroupElement hashToGroup(final byte[] input);

    /**
     * Multiplies a collection of group elements together
     *
     * @param elements the collection of elements to multiply together
     * @return a new group element which is the product the collection of elements
     */
    GroupElement batchMultiply(final Collection<GroupElement> elements);

    /**
     * Creates a group element from its serialized encoding
     *
     * @param bytes serialized form
     * @return the new group element, or null if construction failed
     */
    GroupElement newElementFromBytes(byte[] bytes);

    /**
     * Gets the size in bytes of a compressed group element
     *
     * @return the size of a compressed group element
     */
    int getCompressedSize();

    /**
     * Gets the size in bytes of an uncompressed group element
     *
     * @return the size of an uncompressed group element
     */
    int getUncompressedSize();

    /**
     * Gets the size in bytes of the seed necessary to generate a new element
     *
     * @return the size of a seed needed to generate a new element
     */
    int getSeedSize();
}
