package com.hedera.platform.bls;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {
	private Utils() {
	}

	/**
	 * Computes SHA 256 hash
	 *
	 * @param message
	 * 		message to hash
	 * @return 256-bit hash
	 */
	public static byte[] computeSha256(final byte[] message) {
		try {
			final MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(message);

			return digest.digest();
		} catch (final NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
