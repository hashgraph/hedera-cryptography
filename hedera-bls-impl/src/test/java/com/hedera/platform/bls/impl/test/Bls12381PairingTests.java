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
package com.hedera.platform.bls.impl.test;

import static com.hedera.platform.bls.impl.test.TestUtils.bytesToHex;
import static com.hedera.platform.bls.impl.test.TestUtils.randomByteArray;
import static org.junit.jupiter.api.Assertions.*;

import com.hedera.platform.bls.api.BilinearMap;
import com.hedera.platform.bls.api.GroupElement;
import com.hedera.platform.bls.impl.Bls12381BilinearMap;
import java.util.Random;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class Bls12381PairingTests {
    Random random;
    BilinearMap bilinearMap;

    @BeforeEach
    public void init() {
        random = TestUtils.getRandomPrintSeed();

        bilinearMap = new Bls12381BilinearMap();
    }

    @Test
    @DisplayName("Equal pairing results")
    void equalPairings() {
        final GroupElement signatureElement = bilinearMap
                .signatureGroup()
                .randomElement(
                        randomByteArray(random, bilinearMap.signatureGroup().getSeedSize()));
        final GroupElement keyElement = bilinearMap
                .keyGroup()
                .randomElement(randomByteArray(random, bilinearMap.keyGroup().getSeedSize()));

        Assertions.assertTrue(
                bilinearMap.comparePairing(signatureElement, keyElement, signatureElement, keyElement),
                "pairings should be recognized as equal");
    }

    @Test
    @DisplayName("Unequal pairing results")
    void unequalPairings() {
        final GroupElement signatureElementA = bilinearMap
                .signatureGroup()
                .randomElement(
                        randomByteArray(random, bilinearMap.signatureGroup().getSeedSize()));
        final GroupElement keyElementA = bilinearMap
                .keyGroup()
                .randomElement(randomByteArray(random, bilinearMap.keyGroup().getSeedSize()));

        final GroupElement signatureElementB = bilinearMap
                .signatureGroup()
                .randomElement(
                        randomByteArray(random, bilinearMap.signatureGroup().getSeedSize()));
        final GroupElement keyElementB = bilinearMap
                .keyGroup()
                .randomElement(randomByteArray(random, bilinearMap.keyGroup().getSeedSize()));

        Assertions.assertFalse(
                bilinearMap.comparePairing(signatureElementA, keyElementA, signatureElementB, keyElementB),
                "pairings should be recognized as equal");
    }

    @Test
    @DisplayName("comparePairing failure")
    void comparePairingFailure() {
        final GroupElement signatureElement = bilinearMap
                .signatureGroup()
                .randomElement(
                        randomByteArray(random, bilinearMap.signatureGroup().getSeedSize()));
        final GroupElement keyElement = bilinearMap
                .keyGroup()
                .randomElement(randomByteArray(random, bilinearMap.keyGroup().getSeedSize()));

        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.comparePairing(null, keyElement, signatureElement, keyElement),
                "Pairing comparison should fail with a null element");
        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.comparePairing(signatureElement, null, signatureElement, keyElement),
                "Pairing comparison should fail with a null element");
        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.comparePairing(signatureElement, keyElement, null, keyElement),
                "Pairing comparison should fail with a null element");
        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.comparePairing(signatureElement, keyElement, signatureElement, null),
                "Pairing comparison should fail with a null element");
    }

    @Test
    @DisplayName("comparePairing with compression")
    void comparePairingCompressed() {
        final byte[] seed1 =
                randomByteArray(random, bilinearMap.signatureGroup().getSeedSize());
        final byte[] seed2 = randomByteArray(random, bilinearMap.keyGroup().getSeedSize());

        final GroupElement signatureElement = bilinearMap.signatureGroup().randomElement(seed1);
        final GroupElement keyElement = bilinearMap.keyGroup().randomElement(seed2);

        final GroupElement signatureElementCompressed =
                bilinearMap.signatureGroup().randomElement(seed1).compress();
        final GroupElement keyElementCompressed =
                bilinearMap.keyGroup().randomElement(seed2).compress();

        Assertions.assertTrue(
                bilinearMap.comparePairing(signatureElementCompressed, keyElement, signatureElement, keyElement),
                "compression shouldn't affect pairing equality");
        Assertions.assertTrue(
                bilinearMap.comparePairing(signatureElement, keyElementCompressed, signatureElement, keyElement),
                "compression shouldn't affect pairing equality");
        Assertions.assertTrue(
                bilinearMap.comparePairing(signatureElement, keyElement, signatureElementCompressed, keyElement),
                "compression shouldn't affect pairing equality");
        Assertions.assertTrue(
                bilinearMap.comparePairing(signatureElement, keyElement, signatureElement, keyElementCompressed),
                "compression shouldn't affect pairing equality");
    }

    @Test
    @DisplayName("Different pairings produce unique display strings")
    void pairingDisplayUnique() {
        final GroupElement signatureElementA = bilinearMap
                .signatureGroup()
                .randomElement(
                        randomByteArray(random, bilinearMap.signatureGroup().getSeedSize()));
        final GroupElement keyElementA = bilinearMap
                .keyGroup()
                .randomElement(randomByteArray(random, bilinearMap.keyGroup().getSeedSize()));

        final GroupElement signatureElementB = bilinearMap
                .signatureGroup()
                .randomElement(
                        randomByteArray(random, bilinearMap.signatureGroup().getSeedSize()));
        final GroupElement keyElementB = bilinearMap
                .keyGroup()
                .randomElement(randomByteArray(random, bilinearMap.keyGroup().getSeedSize()));

        assertNotEquals(
                bytesToHex(bilinearMap.displayPairing(signatureElementA, keyElementA)),
                bytesToHex(bilinearMap.displayPairing(signatureElementB, keyElementB)),
                "pairing displays should be unique");
    }

    @Test
    @DisplayName("Identical pairings produce identical display strings")
    void pairingDisplayDeterministic() {
        final GroupElement signatureElement = bilinearMap
                .signatureGroup()
                .randomElement(
                        randomByteArray(random, bilinearMap.signatureGroup().getSeedSize()));
        final GroupElement keyElement = bilinearMap
                .keyGroup()
                .randomElement(randomByteArray(random, bilinearMap.keyGroup().getSeedSize()));

        Assertions.assertArrayEquals(
                bilinearMap.displayPairing(signatureElement, keyElement),
                bilinearMap.displayPairing(signatureElement, keyElement),
                "pairing displays should be identical");
    }

    @Test
    @DisplayName("pairingDisplay failure")
    void pairingDisplayFailure() {
        final GroupElement signatureElement = bilinearMap
                .signatureGroup()
                .randomElement(
                        randomByteArray(random, bilinearMap.signatureGroup().getSeedSize()));
        final GroupElement keyElement = bilinearMap
                .keyGroup()
                .randomElement(randomByteArray(random, bilinearMap.keyGroup().getSeedSize()));

        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.displayPairing(null, keyElement),
                "Pairing display should fail with a null element");
        assertThrows(
                IllegalArgumentException.class,
                () -> bilinearMap.displayPairing(signatureElement, null),
                "Pairing display should fail with a null element");
    }

    @Test
    @DisplayName("pairingDisplay with compression")
    void pairingDisplayCompressed() {
        final byte[] seed1 =
                randomByteArray(random, bilinearMap.signatureGroup().getSeedSize());
        final byte[] seed2 = randomByteArray(random, bilinearMap.keyGroup().getSeedSize());

        final GroupElement signatureElement = bilinearMap.signatureGroup().randomElement(seed1);
        final GroupElement keyElement = bilinearMap.keyGroup().randomElement(seed2);

        final GroupElement signatureElementCompressed =
                bilinearMap.signatureGroup().randomElement(seed1).compress();
        final GroupElement keyElementCompressed =
                bilinearMap.keyGroup().randomElement(seed2).compress();

        final byte[] uncompressedDisplay = bilinearMap.displayPairing(signatureElement, keyElement);

        Assertions.assertArrayEquals(
                uncompressedDisplay,
                bilinearMap.displayPairing(signatureElementCompressed, keyElement),
                "pairing displays should be identical");
        Assertions.assertArrayEquals(
                uncompressedDisplay,
                bilinearMap.displayPairing(signatureElement, keyElementCompressed),
                "pairing displays should be identical");
        Assertions.assertArrayEquals(
                uncompressedDisplay,
                bilinearMap.displayPairing(signatureElementCompressed, keyElementCompressed),
                "pairing displays should be identical");
    }
}
