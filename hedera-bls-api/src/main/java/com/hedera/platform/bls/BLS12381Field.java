package com.hedera.platform.bls;

/**
 * The finite field of the BLS 12-381 curve family
 */
public class BLS12381Field implements Field {
	/**
	 * Required size of a seed to create a new field element
	 */
	public static final int SEED_SIZE = 32;

	/**
	 * Length of a byte array representing a field element
	 */
	public static final int ELEMENT_BYTE_SIZE = 32;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public FieldElement elementFromInt(final int i) {
		final byte[] output = new byte[ELEMENT_BYTE_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381Bindings.newScalarFromInt(i, output)) != 0) {
			throw new BLS12381Exception("newScalarFromInt", errorCode);
		}

		return new BLS12381FieldElement(output, this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public FieldElement zeroElement() {
		final byte[] output = new byte[ELEMENT_BYTE_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381Bindings.newZeroScalar(output)) != 0) {
			throw new BLS12381Exception("newZeroScalar", errorCode);
		}

		return new BLS12381FieldElement(output, this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public FieldElement oneElement() {
		final byte[] output = new byte[ELEMENT_BYTE_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381Bindings.newOneScalar(output)) != 0) {
			throw new BLS12381Exception("newOneScalar", errorCode);
		}

		return new BLS12381FieldElement(output, this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public FieldElement randomElement(final byte[] seed) {
		if (seed.length != SEED_SIZE) {
			throw new IllegalArgumentException(String.format("seed must be %s bytes in length", SEED_SIZE));
		}

		final byte[] output = new byte[ELEMENT_BYTE_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381Bindings.newRandomScalar(seed, output)) != 0) {
			throw new BLS12381Exception("newRandomScalar", errorCode);
		}

		return new BLS12381FieldElement(output, this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public FieldElement deserializeElementFromBytes(final byte[] bytes) {
		final BLS12381FieldElement outputElement = new BLS12381FieldElement(bytes, this);

		if (!outputElement.isValid()) {
			return null;
		}

		return outputElement;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getElementSize() {
		return ELEMENT_BYTE_SIZE;
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
