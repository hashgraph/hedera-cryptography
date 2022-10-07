package com.hedera.platform.bls;

import java.math.BigInteger;

/**
 * An element in {@link BLS12381Field}
 */
public class BLS12381FieldElement implements DistCryptFieldElement {
	/**
	 * The byte representation of the element
	 */
	private final byte[] fieldElement;

	/**
	 * The field the element is in
	 */
	private final BLS12381Field field;

	/**
	 * Package private constructor
	 *
	 * @param fieldElement
	 * 		an array of bytes representing this field element
	 * @param field
	 * 		the field this element is in
	 */
	public BLS12381FieldElement(final byte[] fieldElement, final BLS12381Field field) {
		this.fieldElement = fieldElement;
		this.field = field;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptField getField() {
		return field;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] toBytes() {
		return fieldElement;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptFieldElement add(final DistCryptFieldElement other) {
		final JNICallResult callResult = new JNICallResult(
				BLS12381ScalarBindings.scalarAdd(this, (BLS12381FieldElement) other));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("scalarAdd", callResult.getErrorCode());
		}

		return new BLS12381FieldElement(callResult.getResultArray(), field);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptFieldElement subtract(final DistCryptFieldElement other) {
		final JNICallResult callResult = new JNICallResult(
				BLS12381ScalarBindings.scalarSubtract(this, (BLS12381FieldElement) other));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("scalarSubtract", callResult.getErrorCode());
		}

		return new BLS12381FieldElement(callResult.getResultArray(), field);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptFieldElement multiply(final DistCryptFieldElement other) {
		final JNICallResult callResult = new JNICallResult(
				BLS12381ScalarBindings.scalarMultiply(this, (BLS12381FieldElement) other));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("scalarMultiply", callResult.getErrorCode());
		}

		return new BLS12381FieldElement(callResult.getResultArray(), field);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptFieldElement divide(final DistCryptFieldElement other) {
		final JNICallResult callResult = new JNICallResult(
				BLS12381ScalarBindings.scalarDivide(this, (BLS12381FieldElement) other));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("scalarDivide", callResult.getErrorCode());
		}

		return new BLS12381FieldElement(callResult.getResultArray(), field);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptFieldElement power(final BigInteger exponent) {
		final JNICallResult callResult = new JNICallResult(
				BLS12381ScalarBindings.scalarPower(this, exponent.toByteArray()));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("scalarPower", callResult.getErrorCode());
		}

		return new BLS12381FieldElement(callResult.getResultArray(), field);
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}

		if (o == null) {
			return false;
		}

		if (o instanceof BLS12381FieldElement element) {
			final JNICallResult callResult = new JNICallResult(
					BLS12381ScalarBindings.scalarEquals(this, element));

			if (callResult.getErrorCode() != 0) {
				throw new BLS12381Exception("scalarEquals", callResult.getErrorCode());
			}

			return callResult.getResultArray()[0] == 1 && field.equals(element.field);
		}

		return false;
	}
}
