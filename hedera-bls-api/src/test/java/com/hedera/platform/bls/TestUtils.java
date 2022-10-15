/*
 * Copyright 2016-2022 Hedera Hashgraph, LLC
 *
 * This software is the confidential and proprietary information of
 * Hedera Hashgraph, LLC. ("Confidential Information"). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered into
 * with Hedera Hashgraph.
 *
 * HEDERA HASHGRAPH MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. HEDERA HASHGRAPH SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 */

package com.hedera.platform.bls;

import java.util.Collection;

/**
 * A class containing various utility functions used for testing
 */
public class TestUtils {
	/**
	 * Hidden constructor
	 */
	private TestUtils() {
	}

	/**
	 * Converts a byte array to a hex string
	 *
	 * @param hash
	 * 		the byte array to convert
	 * @return a hex string representing the byte array hash
	 */
	public static String bytesToHex(byte[] hash) {
		StringBuilder hexString = new StringBuilder(2 * hash.length);
		for (byte b : hash) {
			String hex = Integer.toHexString(0xff & b);
			if (hex.length() == 1) {
				hexString.append('0');
			}
			hexString.append(hex);
		}
		return hexString.toString();
	}

	/**
	 * Checks if a collection of objects are all equal to one another
	 *
	 * @param objects
	 * 		the collection of object to compare
	 * @param <T>
	 * 		the type of object contained in the collection
	 * @return true if each object is equal to every other object, otherwise false
	 */
	public static <T> boolean allEqual(Collection<T> objects) {
		if (objects.size() != 0) {
			T reference = null;
			for (T element : objects) {
				if (reference != null && !reference.equals(element)) {
					return false;
				}
				reference = element;
			}
		}
		return true;
	}
}
