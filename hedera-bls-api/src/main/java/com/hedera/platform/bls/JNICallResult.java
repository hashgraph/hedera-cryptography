package com.hedera.platform.bls;

import java.util.Arrays;

/**
 * Class that helps extract the error code, and the returned bytes, from a JNI function call
 */
public class JNICallResult {
	private final int errorCode;
	private final byte[] result;

	public JNICallResult(final byte[] returnedArray) {
		if (returnedArray.length < 1) {
			throw new RuntimeException("Empty array was returned from JNI call. This shouldn't happen.");
		}

		this.errorCode = returnedArray[0];

		if (this.errorCode != 0) {
			// If function returned an error, any other bytes are irrelevant
			this.result = new byte[0];

			return;
		}

		if (returnedArray.length < 2) {
			throw new RuntimeException(
					"JNI call didn't return a result, but error code was empty. This shouldn't happen");
		}

		this.result = Arrays.copyOfRange(returnedArray, 1, returnedArray.length);
	}

	/**
	 * Gets the array representing the return value of the JNI call
	 *
	 * @return the result array
	 */
	public byte[] getResultArray() {
		return result;
	}

	/**
	 * Gets the error code returned by the JNI call
	 *
	 * @return the error code
	 */
	public int getErrorCode() {
		return errorCode;
	}
}
