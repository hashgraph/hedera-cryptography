package com.hedera.platform.bls;

import java.util.Arrays;

/**
 * An element in Group 2 of the BLS 12-381 curve family
 */
public class BLS12381Group2Element implements DistCryptGroupElement {
    /**
     * The bytes representation of the element
     */
    private byte[] groupElement;

    /**
     * The group this element is part of
     */
    private final BLS12381Group2 group;

    /**
     * True if the {@link #groupElement} bytes are in a compressed form, otherwise false
     */
    private boolean compressed;

    /**
     * Package private constructor. This is used by {@link BLS12381Group2}, but shouldn't be called directly by
     * anyone else
     *
     * @param groupElement a byte array representing this group element
     * @param group        the group this element is in
     */
    BLS12381Group2Element(final byte[] groupElement, final BLS12381Group2 group) {
        this.groupElement = groupElement;
        this.group = group;
        this.compressed = groupElement.length == group.getCompressedSize();
    }

    /**
     * Copy constructor
     *
     * @param other the object being copied
     */
    public BLS12381Group2Element(final BLS12381Group2Element other) {
        this.groupElement = Arrays.copyOf(other.groupElement, other.groupElement.length);
        this.group = other.group;
        this.compressed = other.compressed;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DistCryptGroup getGroup() {
        return group;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] toBytes() {
        return groupElement;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DistCryptGroupElement power(final DistCryptFieldElement exponent) {
        final byte[] output = new byte[group.getUncompressedSize()];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g2PowZn(this, (BLS12381FieldElement) exponent, output)) != 0) {
            throw new BLS12381Exception("g2PowZn", errorCode);
        }

        return new BLS12381Group2Element(output, group);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DistCryptGroupElement multiply(final DistCryptGroupElement other) {
        final byte[] output = new byte[group.getUncompressedSize()];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g2Multiply(this, (BLS12381Group2Element) other, output)) != 0) {
            throw new BLS12381Exception("g2Multiply", errorCode);
        }

        return new BLS12381Group2Element(output, group);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DistCryptGroupElement divide(final DistCryptGroupElement other) {
        final byte[] output = new byte[group.getUncompressedSize()];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g2Divide(this, (BLS12381Group2Element) other, output)) != 0) {
            throw new BLS12381Exception("g2Divide", errorCode);
        }

        return new BLS12381Group2Element(output, group);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DistCryptGroupElement compress() {
        // Already compressed, no need to do anything
        if (compressed) {
            return this;
        }

        byte[] newGroupElement = new byte[group.getCompressedSize()];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g2Compress(this, newGroupElement)) != 0) {
            throw new BLS12381Exception("g2Compress", errorCode);
        }

        groupElement = newGroupElement;
        compressed = true;

        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isCompressed() {
        return compressed;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null) {
            return false;
        }

        if (o instanceof BLS12381Group2Element element) {
            return group.equals(element.group) && BLS12381Bindings.g2ElementEquals(this, element);
        }

        return false;
    }

    @Override
    public String toString() {
        return "BLS12381Group2Element{" +
                "bytes=" + (groupElement == null ? null : Arrays.toString(groupElement)) +
                ", group=" + group +
                ", compressed=" + compressed +
                '}';
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public BLS12381Group2Element copy() {
        return new BLS12381Group2Element(this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean checkElementValidity() {
        return (groupElement.length == group.getCompressedSize() || groupElement.length == group.getUncompressedSize())
                && BLS12381Bindings.checkG2Validity(this);
    }
}
