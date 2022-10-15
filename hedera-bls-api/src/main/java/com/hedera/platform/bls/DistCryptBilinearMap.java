package com.hedera.platform.bls;

/**
 * An object for computing bilinear pairings
 */
public interface DistCryptBilinearMap {
	/**
	 * Gets the field of the bilinear map
	 *
	 * @return the field
	 */
	DistCryptField getField();

	/**
	 * Gets the signature group of the map. BLS signatures will be represented as elements of this group
	 *
	 * @return the signature group of the pairing
	 */
	DistCryptGroup getSignatureGroup();

	/**
	 * Gets the key group of the map. BLS public keys will be represented as elements of this group
	 *
	 * @return the key group of the pairing
	 */
	DistCryptGroup getKeyGroup();

	/**
	 * Computes 2 pairings, and then checks the equality of the result
	 *
	 * @param signatureElement1
	 * 		the signature group element of the first pairing
	 * @param keyElement1
	 * 		the key group element of the first pairing
	 * @param signatureElement2
	 * 		the signature group element of the second pairing
	 * @param keyElement2
	 * 		the key group element of the second pairing
	 * @return true if the 2 pairings have the same result, otherwise false
	 */
	boolean comparePairing(
			final DistCryptGroupElement signatureElement1,
			final DistCryptGroupElement keyElement1,
			final DistCryptGroupElement signatureElement2,
			final DistCryptGroupElement keyElement2);

	/**
	 * Computes a pairing, and returns a string representing the result
	 *
	 * @param signatureElement
	 * 		the element in the signature group of the pairing
	 * @param keyElement
	 * 		the element in the key group of the pairing
	 * @return a byte array representing the pairing
	 */
	byte[] displayPairing(
			final DistCryptGroupElement signatureElement,
			final DistCryptGroupElement keyElement
	);
}
