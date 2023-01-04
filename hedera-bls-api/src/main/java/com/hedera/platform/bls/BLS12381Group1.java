package com.hedera.platform.bls;

import java.util.Collection;

/**
 * G1 of the BLS12-381 curve family
 */
public class BLS12381Group1 implements Group {
    /**
     * Length of a byte array representing a compressed element
     */
    private static final int COMPRESSED_SIZE = 48;

    /**
     * Length of a byte array representing an uncompressed element
     */
    private static final int UNCOMPRESSED_SIZE = 96;

    /**
     * Required size of a seed to create a new group element
     */
    private static final int SEED_SIZE = 32;

    /**
     * {@inheritDoc}
     */
    @Override
    public GroupElement newOneElement() {
        final byte[] output = new byte[UNCOMPRESSED_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.newG1Identity(output)) != 0) {
            throw new BLS12381Exception("newG1Identity", errorCode);
        }

        return new BLS12381Group1Element(output, this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public GroupElement newElementFromSeed(final byte[] seed) {
        if (seed.length != SEED_SIZE) {
            throw new IllegalArgumentException(String.format("seed must be %d bytes in length", SEED_SIZE));
        }

        final byte[] output = new byte[UNCOMPRESSED_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.newRandomG1(seed, output)) != 0) {
            throw new BLS12381Exception("newRandomG1", errorCode);
        }

        return new BLS12381Group1Element(output, this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public GroupElement hashToGroup(final byte[] input) {
        return newElementFromSeed(Utils.computeSha256(input));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public GroupElement batchMultiply(final Collection<GroupElement> elements) {
        if (elements.isEmpty()) {
            throw new IllegalArgumentException("Empty collection is invalid");
        }

        final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[elements.size()];

        int count = 0;
        for (final GroupElement element : elements) {
            elementArray[count] = (BLS12381Group1Element) element;
            ++count;
        }

        final byte[] output = new byte[UNCOMPRESSED_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g1BatchMultiply(elementArray, output)) != 0) {
            throw new BLS12381Exception("g1BatchMultiply", errorCode);
        }

        return new BLS12381Group1Element(output, this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public GroupElement newElementFromBytes(final byte[] inputBytes) {
        // create the object, but check validity before returning
        final BLS12381Group1Element outputElement = new BLS12381Group1Element(inputBytes, this);

        if (!outputElement.isValid()) {
            return null;
        }

        return outputElement;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getCompressedSize() {
        return COMPRESSED_SIZE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getUncompressedSize() {
        return UNCOMPRESSED_SIZE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getSeedSize() {
        return SEED_SIZE;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null) {
            return false;
        }

        return getClass() == o.getClass();
    }

    @Override
    public int hashCode() {
        return this.getClass().getCanonicalName().hashCode();
    }
}
