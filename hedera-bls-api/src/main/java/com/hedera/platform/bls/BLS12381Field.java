package com.hedera.platform.bls;

import java.io.IOException;

/**
 * The finite field of the BLS 12-381 curve family
 */
public class BLS12381Field implements DistCryptField {
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
	public DistCryptFieldElement newElement(final int i) {
		final byte[] output = new byte[ELEMENT_BYTE_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381ScalarBindings.newScalarFromInt(i, output)) != 0) {
			throw new BLS12381Exception("newScalarFromInt", errorCode);
		}

		return new BLS12381FieldElement(output, this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptFieldElement newZeroElement() {
		final byte[] output = new byte[ELEMENT_BYTE_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381ScalarBindings.newZeroScalar(output)) != 0) {
			throw new BLS12381Exception("newZeroScalar", errorCode);
		}

		return new BLS12381FieldElement(output, this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptFieldElement newOneElement() {
		final byte[] output = new byte[ELEMENT_BYTE_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381ScalarBindings.newOneScalar(output)) != 0) {
			throw new BLS12381Exception("newOneScalar", errorCode);
		}

		return new BLS12381FieldElement(output, this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptFieldElement newElementFromSeed(final byte[] seed) {
		if (seed.length != SEED_SIZE) {
			throw new IllegalArgumentException(String.format("seed must be %s bytes in length", SEED_SIZE));
		}

		final byte[] output = new byte[ELEMENT_BYTE_SIZE];

		final int errorCode;
		if ((errorCode = BLS12381ScalarBindings.newRandomScalar(seed, output)) != 0) {
			throw new BLS12381Exception("newRandomScalar", errorCode);
		}

		return new BLS12381FieldElement(output, this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptFieldElement newElementFromBytes(final byte[] bytes) throws IOException {
		if (bytes.length != ELEMENT_BYTE_SIZE) {
			throw new IOException("input bytes are of wrong length");
		}

		final BLS12381FieldElement outputElement = new BLS12381FieldElement(bytes, this);

		if (!BLS12381ScalarBindings.checkScalarValidity(outputElement)) {
			throw new BLS12381Exception("checkScalarValidity", 1);
		}

		return outputElement;
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
