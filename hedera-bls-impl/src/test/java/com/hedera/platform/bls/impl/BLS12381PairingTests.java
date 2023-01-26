/*
 * Copyright (C) 2022-2023 Hedera Hashgraph, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hedera.platform.bls.impl;

import static com.hedera.platform.bls.impl.TestUtils.bytesToHex;
import static org.junit.jupiter.api.Assertions.*;

import com.hedera.platform.bls.api.BilinearMap;
import com.hedera.platform.bls.api.Group;
import com.hedera.platform.bls.api.GroupElement;
import java.util.Random;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class BLS12381PairingTests {
    Random random;
    Group group1;
    Group group2;
    BilinearMap bilinearMap;

    @BeforeEach
    public void init() {
        random = TestUtils.getRandomPrintSeed();
        group1 = new BLS12381Group1();
        group2 = new BLS12381Group2();
        bilinearMap = new BLS12381BilinearMap();
    }

    @Test
    @DisplayName("Equal pairing results")
    void equalPairings() {
        final GroupElement group1Element =
                group1.randomElement(TestUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2Element =
                group2.randomElement(TestUtils.randomByteArray(random, group2.getSeedSize()));

        Assertions.assertTrue(
                bilinearMap.comparePairing(
                        group1Element, group2Element, group1Element, group2Element),
                "pairings should be recognized as equal");
    }

    @Test
    @DisplayName("Unequal pairing results")
    void unequalPairings() {
        final GroupElement group1ElementA =
                group1.randomElement(TestUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2ElementA =
                group2.randomElement(TestUtils.randomByteArray(random, group2.getSeedSize()));

        final GroupElement group1ElementB =
                group1.randomElement(TestUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2ElementB =
                group2.randomElement(TestUtils.randomByteArray(random, group2.getSeedSize()));

        Assertions.assertFalse(
                bilinearMap.comparePairing(
                        group1ElementA, group2ElementA, group1ElementB, group2ElementB),
                "pairings should be recognized as equal");
    }

    @Test
    @DisplayName("comparePairing failure")
    void comparePairingFailure() {
        final GroupElement group1Element =
                group1.randomElement(TestUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2Element =
                group2.randomElement(TestUtils.randomByteArray(random, group2.getSeedSize()));

        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.comparePairing(null, group2Element, group1Element, group2Element),
                "Pairing comparison should fail with a null element");
        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.comparePairing(group1Element, null, group1Element, group2Element),
                "Pairing comparison should fail with a null element");
        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.comparePairing(group1Element, group2Element, null, group2Element),
                "Pairing comparison should fail with a null element");
        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.comparePairing(group1Element, group2Element, group1Element, null),
                "Pairing comparison should fail with a null element");
    }

    @Test
    @DisplayName("comparePairing with compression")
    void comparePairingCompressed() {
        final byte[] seed1 = TestUtils.randomByteArray(random, group1.getSeedSize());
        final byte[] seed2 = TestUtils.randomByteArray(random, group2.getSeedSize());

        final GroupElement group1Element = group1.randomElement(seed1);
        final GroupElement group2Element = group2.randomElement(seed2);

        final GroupElement group1ElementCompressed = group1.randomElement(seed1).compress();
        final GroupElement group2ElementCompressed = group2.randomElement(seed2).compress();

        Assertions.assertTrue(
                bilinearMap.comparePairing(
                        group1ElementCompressed, group2Element, group1Element, group2Element),
                "compression shouldn't affect pairing equality");
        Assertions.assertTrue(
                bilinearMap.comparePairing(
                        group1Element, group2ElementCompressed, group1Element, group2Element),
                "compression shouldn't affect pairing equality");
        Assertions.assertTrue(
                bilinearMap.comparePairing(
                        group1Element, group2Element, group1ElementCompressed, group2Element),
                "compression shouldn't affect pairing equality");
        Assertions.assertTrue(
                bilinearMap.comparePairing(
                        group1Element, group2Element, group1Element, group2ElementCompressed),
                "compression shouldn't affect pairing equality");
    }

    @Test
    @DisplayName("Different pairings produce unique display strings")
    void pairingDisplayUnique() {
        final GroupElement group1ElementA =
                group1.randomElement(TestUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2ElementA =
                group2.randomElement(TestUtils.randomByteArray(random, group2.getSeedSize()));

        final GroupElement group1ElementB =
                group1.randomElement(TestUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2ElementB =
                group2.randomElement(TestUtils.randomByteArray(random, group2.getSeedSize()));

        assertNotEquals(
                bytesToHex(bilinearMap.displayPairing(group1ElementA, group2ElementA)),
                bytesToHex(bilinearMap.displayPairing(group1ElementB, group2ElementB)),
                "pairing displays should be unique");
    }

    @Test
    @DisplayName("Identical pairings produce identical display strings")
    void pairingDisplayDeterministic() {
        final GroupElement group1Element =
                group1.randomElement(TestUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2Element =
                group2.randomElement(TestUtils.randomByteArray(random, group2.getSeedSize()));

        Assertions.assertArrayEquals(
                bilinearMap.displayPairing(group1Element, group2Element),
                bilinearMap.displayPairing(group1Element, group2Element),
                "pairing displays should be identical");
    }

    @Test
    @DisplayName("pairingDisplay failure")
    void pairingDisplayFailure() {
        final GroupElement group1Element =
                group1.randomElement(TestUtils.randomByteArray(random, group1.getSeedSize()));
        final GroupElement group2Element =
                group2.randomElement(TestUtils.randomByteArray(random, group2.getSeedSize()));

        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.displayPairing(null, group2Element),
                "Pairing display should fail with a null element");
        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.displayPairing(group1Element, null),
                "Pairing display should fail with a null element");
    }

    @Test
    @DisplayName("pairingDisplay with compression")
    void pairingDisplayCompressed() {
        final byte[] seed1 = TestUtils.randomByteArray(random, group1.getSeedSize());
        final byte[] seed2 = TestUtils.randomByteArray(random, group2.getSeedSize());

        final GroupElement group1Element = group1.randomElement(seed1);
        final GroupElement group2Element = group2.randomElement(seed2);

        final GroupElement group1ElementCompressed = group1.randomElement(seed1).compress();
        final GroupElement group2ElementCompressed = group2.randomElement(seed2).compress();

        final byte[] uncompressedDisplay = bilinearMap.displayPairing(group1Element, group2Element);

        Assertions.assertArrayEquals(
                uncompressedDisplay,
                bilinearMap.displayPairing(group1ElementCompressed, group2Element),
                "pairing displays should be identical");
        Assertions.assertArrayEquals(
                uncompressedDisplay,
                bilinearMap.displayPairing(group1Element, group2ElementCompressed),
                "pairing displays should be identical");
        Assertions.assertArrayEquals(
                uncompressedDisplay,
                bilinearMap.displayPairing(group1ElementCompressed, group2ElementCompressed),
                "pairing displays should be identical");
    }
}
