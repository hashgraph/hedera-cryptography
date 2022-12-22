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
	 * Package private constructor
	 *
	 * @param groupElement
	 * 		a byte array representing this group element
	 * @param group
	 * 		the group this element is in
	 */
	public BLS12381Group2Element(final byte[] groupElement, final BLS12381Group2 group) {
		this.groupElement = groupElement;
		this.group = group;
		this.compressed = groupElement.length == BLS12381Group2.COMPRESSED_SIZE;
	}

	/**
	 * Copy constructor
	 *
	 * @param other
	 * 		the object being copied
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
		final JNICallResult callResult = new JNICallResult(
				BLS12381Group2Bindings.g2PowZn(this, (BLS12381FieldElement) exponent));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("g2PowZn", callResult.getErrorCode());
		}

		return new BLS12381Group2Element(callResult.getResultArray(), group);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement multiply(final DistCryptGroupElement other) {
		final JNICallResult callResult = new JNICallResult(
				BLS12381Group2Bindings.g2Multiply(this, (BLS12381Group2Element) other));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("g2Multiply", callResult.getErrorCode());
		}

		return new BLS12381Group2Element(callResult.getResultArray(), group);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement divide(final DistCryptGroupElement other) {
		final JNICallResult callResult = new JNICallResult(
				BLS12381Group2Bindings.g2Divide(this, (BLS12381Group2Element) other));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("g2Divide", callResult.getErrorCode());
		}

		return new BLS12381Group2Element(callResult.getResultArray(), group);
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

		final JNICallResult callResult =
				new JNICallResult(BLS12381Group2Bindings.g2Compress(this));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("g2Compress", callResult.getErrorCode());
		}

		groupElement = callResult.getResultArray();
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
			final JNICallResult callResult = new JNICallResult(
					BLS12381Group2Bindings.g2ElementEquals(this, element));

			if (callResult.getErrorCode() != 0) {
				throw new BLS12381Exception("g2ElementEquals", callResult.getErrorCode());
			}

			return callResult.getResultArray()[0] == 1;
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
}
