package com.hedera.platform.bls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * G1 of the BLS12-381 curve family
 */
public class BLS12381Group1 implements DistCryptGroup {
	/**
	 * Length of a byte array representing a compressed element
	 */
	public static final int COMPRESSED_SIZE = 48;

	/**
	 * Length of a byte array representing an uncompressed element
	 */
	public static final int UNCOMPRESSED_SIZE = 96;

	/**
	 * Required size of a seed to create a new group element
	 */
	public static final int SEED_SIZE = 32;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement newOneElement() {
		final JNICallResult callResult = new JNICallResult(BLS12381Group1Bindings.newG1Identity());

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("newG1Identity", callResult.getErrorCode());
		}

		return new BLS12381Group1Element(callResult.getResultArray(), this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement newElementFromSeed(final byte[] seed) {
		if (seed.length != SEED_SIZE) {
			throw new IllegalArgumentException(String.format("seed must be %s bytes in length", SEED_SIZE));
		}

		final JNICallResult callResult = new JNICallResult(BLS12381Group1Bindings.newRandomG1(seed));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("newRandomG1", callResult.getErrorCode());
		}

		return new BLS12381Group1Element(callResult.getResultArray(), this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement hashToGroup(final byte[] input) {
		final byte[] hash = Utils.computeSha256(input);

		final JNICallResult callResult = new JNICallResult(BLS12381Group1Bindings.newRandomG1(hash));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("newRandomG1", callResult.getErrorCode());
		}

		return new BLS12381Group1Element(callResult.getResultArray(), this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement batchMultiply(final Collection<DistCryptGroupElement> elements) {
		final List<BLS12381Group1Element> elementList = new ArrayList<>();

		for (final DistCryptGroupElement element : elements) {
			elementList.add((BLS12381Group1Element) element);
		}

		final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[elements.size()];
		elementList.toArray(elementArray);

		final JNICallResult callResult = new JNICallResult(BLS12381Group1Bindings.g1BatchMultiply(elementArray));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("g1BatchMultiply", callResult.getErrorCode());
		}

		return new BLS12381Group1Element(callResult.getResultArray(), this);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptGroupElement newElementFromBytes(final byte[] inputBytes) throws IOException {
		if (inputBytes.length != COMPRESSED_SIZE && inputBytes.length != UNCOMPRESSED_SIZE) {
			throw new IllegalArgumentException(
					String.format("Byte representation of a group 1 element should have compressed length %s, " +
							"or uncompressed length %s", COMPRESSED_SIZE, UNCOMPRESSED_SIZE));
		}

		// create the object, but check validity before returning
		final BLS12381Group1Element outputElement = new BLS12381Group1Element(inputBytes, this);

		final JNICallResult callResult = new JNICallResult(BLS12381Group1Bindings.checkG1Validity(outputElement));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("checkG1Validity", callResult.getErrorCode());
		}

		if (callResult.getResultArray()[0] == 0) {
			throw new IOException("input bytes don't represent a valid g1 element");
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
