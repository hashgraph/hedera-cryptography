package com.hedera.platform.bls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * G2 of the BLS12-381 curve family
 */
public class BLS12381Group2 implements DistCryptGroup {
	/**
	 * Length of a byte array representing a compressed element
	 */
	public static final int COMPRESSED_SIZE = 96;

	/**
	 * Length of a byte array representing an uncompressed element
	 */
	public static final int UNCOMPRESSED_SIZE = 192;

	/**
	 * Required size of a seed to create a new group element
	 */
	public static final int SEED_SIZE = 32;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement newOneElement() {
		final JNICallResult callResult = new JNICallResult(BLS12381Group2Bindings.newG2Identity());

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("newG2Identity", callResult.getErrorCode());
		}

		return new BLS12381Group2Element(callResult.getResultArray(), this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement newElementFromSeed(final byte[] seed) {
		if (seed.length != SEED_SIZE) {
			throw new IllegalArgumentException(String.format("seed must be %s bytes in length", SEED_SIZE));
		}

		final JNICallResult callResult = new JNICallResult(BLS12381Group2Bindings.newRandomG2(seed));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("newRandomG2", callResult.getErrorCode());
		}

		return new BLS12381Group2Element(callResult.getResultArray(), this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement hashToGroup(final byte[] input) {
		final byte[] hash = Utils.computeSha256(input);

		final JNICallResult callResult = new JNICallResult(BLS12381Group2Bindings.newRandomG2(hash));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("newRandomG2", callResult.getErrorCode());
		}

		return new BLS12381Group2Element(callResult.getResultArray(), this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement batchMultiply(final Collection<DistCryptGroupElement> elements) {
		final List<BLS12381Group2Element> elementList = new ArrayList<>();

		for (final DistCryptGroupElement element : elements) {
			elementList.add((BLS12381Group2Element) element);
		}

		final BLS12381Group2Element[] elementArray = new BLS12381Group2Element[elements.size()];
		elementList.toArray(elementArray);

		final JNICallResult callResult = new JNICallResult(BLS12381Group2Bindings.g2BatchMultiply(elementArray));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("g2BatchMultiply", callResult.getErrorCode());
		}

		return new BLS12381Group2Element(callResult.getResultArray(), this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement newElementFromBytes(final byte[] inputBytes) throws IOException {
		if (inputBytes.length != COMPRESSED_SIZE && inputBytes.length != UNCOMPRESSED_SIZE) {
			throw new IllegalArgumentException(
					String.format("Byte representation of a group 2 element should have compressed length %s, " +
							"or uncompressed length %s", COMPRESSED_SIZE, UNCOMPRESSED_SIZE));
		}

		// create the object, but check validity before returning
		final BLS12381Group2Element outputElement = new BLS12381Group2Element(inputBytes, this);

		final JNICallResult callResult = new JNICallResult(BLS12381Group2Bindings.checkG2Validity(outputElement));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("checkG2Validity", callResult.getErrorCode());
		}

		if (callResult.getResultArray()[0] == 0) {
			throw new IOException("input bytes don't represent a valid g2 element");
		}

		return outputElement;
	}

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
