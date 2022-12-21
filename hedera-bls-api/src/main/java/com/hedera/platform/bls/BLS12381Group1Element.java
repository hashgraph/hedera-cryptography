package com.hedera.platform.bls;

import java.util.Arrays;

/**
 * An element in Group 1 of the BLS 12-381 curve family
 */
public class BLS12381Group1Element implements DistCryptGroupElement {
	/**
	 * The bytes representation of the element
	 */
	private byte[] groupElement;

	/**
	 * The group this element is part of
	 */
	private final BLS12381Group1 group;

	/**
	 * True if the {@link #groupElement} bytes are in a compressed form, otherwise false
	 */
	private boolean compressed;

	/**
	 * Package private constructor
	 *
	 * @param groupElement
	 * 		a byte array representing this group element
	 * @param group
	 * 		the group this element is in
	 */
	public BLS12381Group1Element(final byte[] groupElement, final BLS12381Group1 group) {
		this.groupElement = groupElement;
		this.group = group;
		this.compressed = groupElement.length == BLS12381Group1.COMPRESSED_SIZE;
	}

	/**
	 * Copy constructor
	 *
	 * @param other
	 * 		the object being copied
	 */
	public BLS12381Group1Element(final BLS12381Group1Element other) {
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
		final byte[] output = new byte[BLS12381Group1.UNCOMPRESSED_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381Group1Bindings.g1PowZn(this, (BLS12381FieldElement) exponent, output)) != 0) {
			throw new BLS12381Exception("g1PowZn", errorCode);
		}

		return new BLS12381Group1Element(output, group);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement multiply(final DistCryptGroupElement other) {
		final byte[] output = new byte[BLS12381Group1.UNCOMPRESSED_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381Group1Bindings.g1Multiply(this, (BLS12381Group1Element) other, output)) != 0) {
			throw new BLS12381Exception("g1Multiply", errorCode);
		}

		return new BLS12381Group1Element(output, group);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement divide(final DistCryptGroupElement other) {
		final byte[] output = new byte[BLS12381Group1.UNCOMPRESSED_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381Group1Bindings.g1Divide(this, (BLS12381Group1Element) other, output)) != 0) {
			throw new BLS12381Exception("g1Divide", errorCode);
		}

		return new BLS12381Group1Element(output, group);
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

		byte[] newGroupElement = new byte[BLS12381Group1.COMPRESSED_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381Group1Bindings.g1Compress(this, newGroupElement)) != 0) {
			throw new BLS12381Exception("g1Compress", errorCode);
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

		if (o instanceof BLS12381Group1Element element) {
			return group.equals(element.group) && BLS12381Group1Bindings.g1ElementEquals(this, element);
		}

		return false;
	}

	@Override
	public String toString() {
		return "com.hedera.bls.BLS12381Group1Element{" +
				"groupElement=" + (groupElement == null ? null : Arrays.toString(groupElement)) +
				", group=" + group +
				", compressed=" + compressed +
				'}';
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public BLS12381Group1Element copy() {
		return new BLS12381Group1Element(this);
	}
}
