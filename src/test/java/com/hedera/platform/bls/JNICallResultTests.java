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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JNICallResultTests {
	@Test
	@DisplayName("constructor success")
	void constructorSuccess() {
		final byte[] testBytes = new byte[3];

		// add some test data after error code of 0
		testBytes[1] = 0x1;
		testBytes[2] = 0x2;

		final JNICallResult callResult = new JNICallResult(testBytes);

		assertEquals(0, callResult.getErrorCode(), "error code should be 0");

		final byte[] resultArray = callResult.getResultArray();

		assertEquals(2, resultArray.length, "incorrect result array length");

		// verify that data was copied correctly
		assertEquals(0x1, resultArray[0], "incorrect byte value");
		assertEquals(0x2, resultArray[1], "incorrect byte value");
	}

	@Test
	@DisplayName("constructor for empty input")
	void emptyInputTest() {
		assertThrows(RuntimeException.class, () -> new JNICallResult(new byte[0]),
				"constructor with empty input array should cause exception");
	}

	@Test
	@DisplayName("constructor for input with error code")
	void errorCodeInput() {
		final byte[] testBytes = new byte[3];
		testBytes[0] = 0x1;

		final JNICallResult callResult = new JNICallResult(testBytes);

		assertEquals(0x1, callResult.getErrorCode(), "error code should be 1");
		assertEquals(0, callResult.getResultArray().length, "result array should be empty");
	}

	@Test
	@DisplayName("constructor with no error code but empty result")
	void malformedInput() {
		// testBytes have no error code, and also no other data
		final byte[] testBytes = new byte[1];

		assertThrows(RuntimeException.class, () -> new JNICallResult(testBytes),
				"input array with no error code and no result should cause exception");
	}
}
