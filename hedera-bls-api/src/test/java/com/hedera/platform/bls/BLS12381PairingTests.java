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

import java.util.Random;

import static com.hedera.platform.bls.TestUtils.bytesToHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class BLS12381PairingTests {
	@Test
	@DisplayName("Equal pairing results")
	void equalPairings() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element group1Element = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element group2Element = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertBooleanCallTrue(
				BLS12381PairingBindings.comparePairing(group1Element, group2Element, group1Element, group2Element),
				"pairings should be recognized as equal");
	}

	@Test
	@DisplayName("Unequal pairing results")
	void unequalPairings() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element group1ElementA = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element group2ElementA = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element group1ElementB = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element group2ElementB = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertBooleanCallFalse(
				BLS12381PairingBindings.comparePairing(group1ElementA, group2ElementA, group1ElementB, group2ElementB),
				"pairings should not be equal");
	}

	@Test
	@DisplayName("comparePairing failure")
	void comparePairingFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element group1Element = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element group2Element = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		JNITestUtils.assertErrorFromCall(
				BLS12381PairingBindings.comparePairing(null, group2Element, group1Element, group2Element), 1);
		JNITestUtils.assertErrorFromCall(
				BLS12381PairingBindings.comparePairing(group1Element, null, group1Element, group2Element), 1);
		JNITestUtils.assertErrorFromCall(
				BLS12381PairingBindings.comparePairing(group1Element, group2Element, null, group2Element), 1);
		JNITestUtils.assertErrorFromCall(
				BLS12381PairingBindings.comparePairing(group1Element, group2Element, group1Element, null), 1);
	}

	@Test
	@DisplayName("comparePairing with compression")
	void comparePairingCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element group1Element = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element group2Element = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element group1ElementCompressed = JNITestUtils.g1Compress(group1Element);
		final BLS12381Group2Element group2ElementCompressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(group2Element));

		JNITestUtils.assertBooleanCallTrue(BLS12381PairingBindings.comparePairing(
						group1ElementCompressed, group2Element, group1Element, group2Element),
				"compression shouldn't affect equality");
		JNITestUtils.assertBooleanCallTrue(BLS12381PairingBindings.comparePairing(
						group1Element, group2ElementCompressed, group1Element, group2Element),
				"compression shouldn't affect equality");
		JNITestUtils.assertBooleanCallTrue(BLS12381PairingBindings.comparePairing(
						group1Element, group2Element, group1ElementCompressed, group2Element),
				"compression shouldn't affect equality");
		JNITestUtils.assertBooleanCallTrue(BLS12381PairingBindings.comparePairing(
						group1Element, group2Element, group1Element, group2ElementCompressed),
				"compression shouldn't affect equality");
	}

	@Test
	@DisplayName("Different pairings produce unique display strings")
	void pairingDisplayUnique() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element group1ElementA = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element group2ElementA = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element group1ElementB = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element group2ElementB = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		assertNotEquals(
				bytesToHex(BLS12381PairingBindings.pairingDisplay(group1ElementA, group2ElementA)),
				bytesToHex(BLS12381PairingBindings.pairingDisplay(group1ElementB, group2ElementB)),
				"pairing displays should be unique");
	}

	@Test
	@DisplayName("Identical pairings produce identical display strings")
	void pairingDisplayDeterministic() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element group1Element = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element group2Element = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		assertArrayEquals(
				BLS12381PairingBindings.pairingDisplay(group1Element, group2Element),
				BLS12381PairingBindings.pairingDisplay(group1Element, group2Element),
				"pairing displays should be identical");
	}

	@Test
	@DisplayName("pairingDisplay failure")
	void pairingDisplayFailure() {
		final Random random = RandomUtils.getRandomPrintSeed();

		JNITestUtils.assertErrorFromCall(BLS12381PairingBindings.pairingDisplay(
				JNITestUtils.getG1RandomElement(RandomUtils.randomByteArray(random, 32)), null), 1);
		JNITestUtils.assertErrorFromCall(BLS12381PairingBindings.pairingDisplay(
				null, JNITestUtils.getG2RandomElement(RandomUtils.randomByteArray(random, 32))), 1);
	}

	@Test
	@DisplayName("pairingDisplay with compression")
	void pairingDisplayCompressed() {
		final Random random = RandomUtils.getRandomPrintSeed();

		final BLS12381Group1Element group1Element = JNITestUtils.getG1RandomElement(
				RandomUtils.randomByteArray(random, 32));
		final BLS12381Group2Element group2Element = JNITestUtils.getG2RandomElement(
				RandomUtils.randomByteArray(random, 32));

		final BLS12381Group1Element group1ElementCompressed = JNITestUtils.g1Compress(group1Element);
		final BLS12381Group2Element group2ElementCompressed = JNITestUtils.getG2ElementFromCall(
				BLS12381Group2Bindings.g2Compress(group2Element));

		final byte[] uncompressedDisplay = BLS12381PairingBindings.pairingDisplay(group1Element, group2Element);

		assertArrayEquals(uncompressedDisplay,
				BLS12381PairingBindings.pairingDisplay(group1ElementCompressed, group2Element),
				"pairing displays should be identical");
		assertArrayEquals(uncompressedDisplay,
				BLS12381PairingBindings.pairingDisplay(group1Element, group2ElementCompressed),
				"pairing displays should be identical");
		assertArrayEquals(uncompressedDisplay,
				BLS12381PairingBindings.pairingDisplay(group1ElementCompressed, group2ElementCompressed),
				"pairing displays should be identical");
	}
}
