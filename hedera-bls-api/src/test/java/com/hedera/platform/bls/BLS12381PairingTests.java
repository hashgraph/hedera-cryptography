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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static com.hedera.platform.bls.TestUtils.bytesToHex;
import static org.junit.jupiter.api.Assertions.*;

class BLS12381PairingTests {
    Random random;
    Group group1;
    Group group2;
    BilinearMap bilinearMap;

    @BeforeEach
    public void init() {
        random = RandomUtils.getRandomPrintSeed();
        group1 = new BLS12381Group1();
        group2 = new BLS12381Group2();
        bilinearMap = new BLS12381BilinearMap();
    }

    @Test
    @DisplayName("Equal pairing results")
    void equalPairings() {
        final GroupElement group1Element = group1.newElementFromSeed(
                RandomUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2Element = group2.newElementFromSeed(
                RandomUtils.randomByteArray(random, group2.getSeedSize()));

        assertTrue(bilinearMap.comparePairing(group1Element, group2Element, group1Element, group2Element),
                "pairings should be recognized as equal");
    }

    @Test
    @DisplayName("Unequal pairing results")
    void unequalPairings() {
        final GroupElement group1ElementA = group1.newElementFromSeed(
                RandomUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2ElementA = group2.newElementFromSeed(
                RandomUtils.randomByteArray(random, group2.getSeedSize()));

        final GroupElement group1ElementB = group1.newElementFromSeed(
                RandomUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2ElementB = group2.newElementFromSeed(
                RandomUtils.randomByteArray(random, group2.getSeedSize()));

        assertFalse(bilinearMap.comparePairing(group1ElementA, group2ElementA, group1ElementB, group2ElementB),
                "pairings should be recognized as equal");
    }

    @Test
    @DisplayName("comparePairing failure")
    void comparePairingFailure() {
        final GroupElement group1Element = group1.newElementFromSeed(
                RandomUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2Element = group2.newElementFromSeed(
                RandomUtils.randomByteArray(random, group2.getSeedSize()));

        assertThrows(BLS12381Exception.class, () -> bilinearMap.comparePairing(
                        null, group2Element, group1Element, group2Element),
                "Pairing comparison should fail with a null element");
        assertThrows(BLS12381Exception.class, () -> bilinearMap.comparePairing(
                        group1Element, null, group1Element, group2Element),
                "Pairing comparison should fail with a null element");
        assertThrows(BLS12381Exception.class, () -> bilinearMap.comparePairing(
                        group1Element, group2Element, null, group2Element),
                "Pairing comparison should fail with a null element");
        assertThrows(BLS12381Exception.class, () -> bilinearMap.comparePairing(
                        group1Element, group2Element, group1Element, null),
                "Pairing comparison should fail with a null element");
    }

    @Test
    @DisplayName("comparePairing with compression")
    void comparePairingCompressed() {
        final byte[] seed1 = RandomUtils.randomByteArray(random, group1.getSeedSize());
        final byte[] seed2 = RandomUtils.randomByteArray(random, group2.getSeedSize());

        final GroupElement group1Element = group1.newElementFromSeed(seed1);
        final GroupElement group2Element = group2.newElementFromSeed(seed2);

        final GroupElement group1ElementCompressed = group1.newElementFromSeed(seed1).compress();
        final GroupElement group2ElementCompressed = group2.newElementFromSeed(seed2).compress();

        assertTrue(bilinearMap.comparePairing(group1ElementCompressed, group2Element, group1Element, group2Element),
                "compression shouldn't affect pairing equality");
        assertTrue(bilinearMap.comparePairing(group1Element, group2ElementCompressed, group1Element, group2Element),
                "compression shouldn't affect pairing equality");
        assertTrue(bilinearMap.comparePairing(group1Element, group2Element, group1ElementCompressed, group2Element),
                "compression shouldn't affect pairing equality");
        assertTrue(bilinearMap.comparePairing(group1Element, group2Element, group1Element, group2ElementCompressed),
                "compression shouldn't affect pairing equality");
    }

    @Test
    @DisplayName("Different pairings produce unique display strings")
    void pairingDisplayUnique() {
        final GroupElement group1ElementA = group1.newElementFromSeed(
                RandomUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2ElementA = group2.newElementFromSeed(
                RandomUtils.randomByteArray(random, group2.getSeedSize()));

        final GroupElement group1ElementB = group1.newElementFromSeed(
                RandomUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2ElementB = group2.newElementFromSeed(
                RandomUtils.randomByteArray(random, group2.getSeedSize()));

        assertNotEquals(
                bytesToHex(bilinearMap.displayPairing(group1ElementA, group2ElementA)),
                bytesToHex(bilinearMap.displayPairing(group1ElementB, group2ElementB)),
                "pairing displays should be unique");
    }

    @Test
    @DisplayName("Identical pairings produce identical display strings")
    void pairingDisplayDeterministic() {
        final GroupElement group1Element = group1.newElementFromSeed(
                RandomUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2Element = group2.newElementFromSeed(
                RandomUtils.randomByteArray(random, group2.getSeedSize()));

        assertArrayEquals(
                bilinearMap.displayPairing(group1Element, group2Element),
                bilinearMap.displayPairing(group1Element, group2Element),
                "pairing displays should be identical");
    }

    @Test
    @DisplayName("pairingDisplay failure")
    void pairingDisplayFailure() {
        final GroupElement group1Element = group1.newElementFromSeed(
                RandomUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2Element = group2.newElementFromSeed(
                RandomUtils.randomByteArray(random, group2.getSeedSize()));

        assertThrows(BLS12381Exception.class, () -> bilinearMap.displayPairing(null, group2Element),
                "Pairing display should fail with a null element");
        assertThrows(BLS12381Exception.class, () -> bilinearMap.displayPairing(group1Element, null),
                "Pairing display should fail with a null element");
    }

    @Test
    @DisplayName("pairingDisplay with compression")
    void pairingDisplayCompressed() {
        final byte[] seed1 = RandomUtils.randomByteArray(random, group1.getSeedSize());
        final byte[] seed2 = RandomUtils.randomByteArray(random, group2.getSeedSize());

        final GroupElement group1Element = group1.newElementFromSeed(seed1);
        final GroupElement group2Element = group2.newElementFromSeed(seed2);

        final GroupElement group1ElementCompressed = group1.newElementFromSeed(seed1).compress();
        final GroupElement group2ElementCompressed = group2.newElementFromSeed(seed2).compress();

        final byte[] uncompressedDisplay = bilinearMap.displayPairing(group1Element, group2Element);

        assertArrayEquals(uncompressedDisplay, bilinearMap.displayPairing(group1ElementCompressed, group2Element),
                "pairing displays should be identical");
        assertArrayEquals(uncompressedDisplay, bilinearMap.displayPairing(group1Element, group2ElementCompressed),
                "pairing displays should be identical");
        assertArrayEquals(uncompressedDisplay, bilinearMap.displayPairing(
                        group1ElementCompressed, group2ElementCompressed),
                "pairing displays should be identical");
    }
}
