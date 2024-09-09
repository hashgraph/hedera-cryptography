/*
 * Copyright (C) 2024 Hedera Hashgraph, LLC
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

package com.hedera.cryptography.pairings.signatures.api;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.api.curves.KnownCurves;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Arrays;
import java.util.Random;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class SignaturesLibraryTest {

    @Test
    void testFindAltBn128Provider() {
        assertDoesNotThrow(() -> PairingFriendlyCurves.findInstance(KnownCurves.ALT_BN128));
        assertEquals(
                KnownCurves.ALT_BN128,
                PairingFriendlyCurves.findInstance(Curve.ALT_BN128)
                        .pairingFriendlyCurve()
                        .curve());
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void crateSignatureSchema(GroupAssignment assignment) {
        final var actual = SignatureSchema.create(Curve.ALT_BN128, assignment);
        assertNotNull(actual);
        assertNotNull(actual.getPairingFriendlyCurve());

        assertEquals(
                PairingFriendlyCurves.findInstance(Curve.ALT_BN128).pairingFriendlyCurve(),
                actual.getPairingFriendlyCurve());
        final var g1 = actual.getPairingFriendlyCurve().group1();
        assertEquals(
                g1,
                assignment == GroupAssignment.SHORT_PUBLIC_KEYS
                        ? actual.getPublicKeyGroup()
                        : actual.getSignatureGroup());
        final var other = SignatureSchema.create(
                Curve.ALT_BN128,
                assignment == GroupAssignment.SHORT_SIGNATURES
                        ? GroupAssignment.SHORT_PUBLIC_KEYS
                        : GroupAssignment.SHORT_SIGNATURES);
        assertNotNull(other);
        assertNotNull(other.getPairingFriendlyCurve());
        final var g2 = other.getPairingFriendlyCurve().group2();
        assertEquals(
                g2,
                assignment == GroupAssignment.SHORT_PUBLIC_KEYS
                        ? other.getPublicKeyGroup()
                        : other.getSignatureGroup());

        assertNotEquals(actual.getIdByte(), other.getIdByte());

        assertEquals(actual, SignatureSchema.create(actual.getIdByte()));
        assertEquals(other, SignatureSchema.create(other.getIdByte()));
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void crateKeyPairTest(GroupAssignment assignment) {
        final var schema = SignatureSchema.create(Curve.ALT_BN128, assignment);
        final var rng = new Random();

        final var sk = PairingPrivateKey.create(schema, rng);
        assertNotNull(sk);
        assertNotNull(sk.toBytes());
        assertNotNull(sk.createPublicKey());
        assertNotNull(sk.toBytes());

        final var pk = sk.createPublicKey();
        assertEquals(pk, sk.createPublicKey());

        final byte[] invalidKey = new byte[0];
        assertThrows(IllegalArgumentException.class, () -> PairingPrivateKey.fromBytes(invalidKey));
        final byte[] invalidKey2 = new byte[] {schema.getIdByte(), 0, 0, 0, 0};
        assertThrows(IllegalArgumentException.class, () -> PairingPrivateKey.fromBytes(invalidKey2));

        assertEquals(sk, PairingPrivateKey.fromBytes(sk.toBytes()));
        assertEquals(pk, PairingPublicKey.fromBytes(pk.toBytes()));
        assertThrows(IllegalArgumentException.class, () -> PairingPublicKey.fromBytes(invalidKey));
        assertThrows(IllegalArgumentException.class, () -> PairingPublicKey.fromBytes(invalidKey2));

        flipEachBitAndDo(
                sk.toBytes(),
                val -> assertThrows(IllegalArgumentException.class, () -> PairingPublicKey.fromBytes(val)));
        flipEachBitAndDo(
                pk.toBytes(),
                val -> assertThrows(IllegalArgumentException.class, () -> PairingPublicKey.fromBytes(val)));
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void crateSignatureTest(GroupAssignment assignment) {
        final var schema = SignatureSchema.create(Curve.ALT_BN128, assignment);
        final var rng = new Random();

        final var sk = PairingPrivateKey.create(schema, rng);

        var message = new byte[256];
        rng.nextBytes(message);

        final var signature = sk.sign(message);
        assertNotNull(signature);
        assertNotNull(signature.toBytes());
        assertEquals(signature, sk.sign(message));
        flipEachBitAndDo(
                signature.toBytes(),
                val -> assertThrows(IllegalArgumentException.class, () -> PairingSignature.fromBytes(val)));

        assertEquals(signature, PairingSignature.fromBytes(signature.toBytes()));

        final byte[] invalidSignature = new byte[0];
        final byte[] invalidSignature2 = new byte[] {schema.getIdByte(), 0, 0, 0, 0};
        assertThrows(IllegalArgumentException.class, () -> PairingSignature.fromBytes(invalidSignature));
        assertThrows(IllegalArgumentException.class, () -> PairingSignature.fromBytes(invalidSignature2));
    }

    /**
     * Flip each byte of an array individually and invoke the consumer on each flip
     * @param array the array with where the flipping will occur. The array is modified
     * @param consumer the consumer to invoke on each flip
     */
    void flipEachBitAndDo(@NonNull byte[] array, final @NonNull Consumer<byte[]> consumer) {

        for (int i = 0; i < array.length; i++) {
            byte flippedByte = 0; // Temporary byte to store flipped bits
            byte originalByte = array[i];
            for (int bitPosition = 0; bitPosition < 8; bitPosition++) {
                int currentBit = (array[i] >> bitPosition) & 1;

                int flippedBit = currentBit == 0 ? 1 : 0;

                flippedByte |= (byte) (flippedBit << bitPosition);
                array[i] = flippedByte;
                consumer.accept(array);
            }
            array[i] = originalByte;
        }
    }

    private static Stream<GroupAssignment> combinedParameters() {
        return Arrays.stream(GroupAssignment.values());
    }
}
