package com.hedera.platform.bls;

import java.util.HashMap;
import java.util.Map;

/**
 * Exception thrown when the BLS12_381 library encounters an unexpected error
 */
public class BLS12381Exception extends RuntimeException {
	/**
	 * A static map between error code and error string
	 */
	private static final Map<Integer, String> errorCodeMap;

	static {
		errorCodeMap = new HashMap<>();
		errorCodeMap.put(1, "JNI");
		errorCodeMap.put(2, "TryFromSlice");
		errorCodeMap.put(3, "TryInto");
		errorCodeMap.put(4, "InputLength");
		errorCodeMap.put(5, "Deserialization");
		errorCodeMap.put(6, "Computation");
		errorCodeMap.put(7, "ArraySize");
	}

	/**
	 * Constructor
	 *
	 * @param functionName
	 * 		the name of the library function where the error occurred
	 * @param errorCode
	 * 		the error code that was returned
	 */
	public BLS12381Exception(final String functionName, final int errorCode) {
		super(functionName + " returned error [" + errorCode + ": "
				+ errorCodeMap.getOrDefault(errorCode, "unknown") + "]");
	}
}
