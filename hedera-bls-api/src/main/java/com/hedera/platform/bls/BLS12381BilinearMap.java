package com.hedera.platform.bls;

/**
 * A bilinear map in the BLS 12-381 family of curves
 */
public final class BLS12381BilinearMap implements DistCryptBilinearMap {
	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistCryptField getField() {
		return new BLS12381Field();
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Since elements are smaller and faster to operate on, we are using {@link BLS12381Group1} as our signature group.
	 * More operations are performed with signatures than with keys
	 */
	@Override
	public DistCryptGroup getSignatureGroup() {
		return new BLS12381Group1();
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Since elements are larger and slower to operate on, we are using {@link BLS12381Group2} as our key group. Fewer
	 * operations are performed with keys than with signatures
	 */
	@Override
	public DistCryptGroup getKeyGroup() {
		return new BLS12381Group2();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean comparePairing(
			final DistCryptGroupElement signatureElement1,
			final DistCryptGroupElement keyElement1,
			final DistCryptGroupElement signatureElement2,
			final DistCryptGroupElement keyElement2) {

		final JNICallResult callResult = new JNICallResult(
				BLS12381Bindings.comparePairing(
						(BLS12381Group1Element) signatureElement1,
						(BLS12381Group2Element) keyElement1,
						(BLS12381Group1Element) signatureElement2,
						(BLS12381Group2Element) keyElement2));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("comparePairing", callResult.getErrorCode());
		}

		return callResult.getResultArray()[0] == 1;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] displayPairing(final DistCryptGroupElement signatureElement, final DistCryptGroupElement keyElement) {
		final JNICallResult callResult = new JNICallResult(BLS12381Bindings.pairingDisplay(
				(BLS12381Group1Element) signatureElement, (BLS12381Group2Element) keyElement));

		if (callResult.getErrorCode() != 0) {
			throw new BLS12381Exception("pairingDisplay", callResult.getErrorCode());
		}

		return callResult.getResultArray();
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

	@Override
	public String toString() {
		return this.getClass().getCanonicalName();
	}
}
