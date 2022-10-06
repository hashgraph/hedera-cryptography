package com.hedera.platform.bls;

import java.util.ArrayList;
import java.util.List;

import static com.hedera.platform.bls.LibraryLoader.Mode.PREFER_BUNDLED;

public final class BLS12381PairingBindings {
	private BLS12381PairingBindings() {
	}

	/**
	 * Computes 2 separate pairings, A and B, and checks the resulting elements for equality
	 *
	 * @param g1a
	 * 		the g1 group element for pairing A
	 * @param g2a
	 * 		the g2 group element for pairing A
	 * @param g1b
	 * 		the g1 group element for pairing B
	 * @param g2b
	 * 		the g2 group element for pairing B
	 * @return a byte array with byte 0 being an error code, and the second byte representing the equality of the 2
	 * 		pairings, A and B. A value of 1 indicates equality, and a value of 0 indicates inequality
	 */
	public static native byte[] comparePairing(
			final BLS12381Group1Element g1a,
			final BLS12381Group2Element g2a,
			final BLS12381Group1Element g1b,
			final BLS12381Group2Element g2b);

	/**
	 * Computes a pairing, and returns a byte representation of the result
	 *
	 * @param g1
	 * 		the g1 group element for the pairing
	 * @param g2
	 * 		the g2 group element for the pairing
	 * @return a byte array with byte 0 being an error code, and the remaining bytes representing a serialized
	 * 		version of the pairing result
	 */
	public static native byte[] pairingDisplay(final BLS12381Group1Element g1, final BLS12381Group2Element g2);

	static {
		final List<Class> classList = new ArrayList<>();
		classList.add(BLS12381PairingBindings.class);

		new LibraryLoader(classList).loadLibrary(PREFER_BUNDLED, "pairings_jni_rust");
	}
}
