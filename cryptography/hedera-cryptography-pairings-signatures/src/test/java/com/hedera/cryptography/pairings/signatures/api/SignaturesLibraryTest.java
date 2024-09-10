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
                        .curve(),
                "The pairing friendly curve should be ALT_BN128");
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void crateSignatureSchema(GroupAssignment assignment) {
        final var actual = SignatureSchema.create(Curve.ALT_BN128, assignment);
        assertNotNull(actual, "Should have created a SignatureSchema");
        assertNotNull(actual.getPairingFriendlyCurve(), "Should have created a pairing friendly curve instance");

        assertEquals(
                PairingFriendlyCurves.findInstance(Curve.ALT_BN128).pairingFriendlyCurve(),
                actual.getPairingFriendlyCurve(),
                "PairingFriendlyCurve should be a singleton");
        final var g1 = actual.getPairingFriendlyCurve().group1();
        assertEquals(
                g1,
                assignment == GroupAssignment.SHORT_PUBLIC_KEYS
                        ? actual.getPublicKeyGroup()
                        : actual.getSignatureGroup(),
                "group1 assignment validation failed for: " + assignment);
        final var other = SignatureSchema.create(
                Curve.ALT_BN128,
                assignment == GroupAssignment.SHORT_SIGNATURES
                        ? GroupAssignment.SHORT_PUBLIC_KEYS
                        : GroupAssignment.SHORT_SIGNATURES);
        assertNotNull(other, "Should have created a SignatureSchema");
        assertNotNull(other.getPairingFriendlyCurve(), "should have created a pairing friendly curve instance");
        assertNotEquals(
                actual.getIdByte(),
                other.getIdByte(),
                "different idBytes expected when different assignments are used");
        final var g2 = other.getPairingFriendlyCurve().group2();
        assertEquals(
                g2,
                assignment == GroupAssignment.SHORT_PUBLIC_KEYS ? other.getPublicKeyGroup() : other.getSignatureGroup(),
                "group2 assignment validation failed for: " + assignment);

        assertEquals(
                actual, SignatureSchema.create(actual.getIdByte()), "creation from idByte should return same instance");
        assertEquals(
                other, SignatureSchema.create(other.getIdByte()), "creation from idByte should return same instance");
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

        final var pk = sk.createPublicKey();
        assertEquals(pk, sk.createPublicKey(), "public key should be deterministic");

        final byte[] invalidKey = new byte[0];
        assertThrows(
                IllegalArgumentException.class,
                () -> PairingPrivateKey.fromBytes(invalidKey),
                "Invalid key should throw an exception");
        final byte[] invalidKey2 = new byte[] {schema.getIdByte(), 0, 0, 0, 0};
        assertThrows(
                IllegalArgumentException.class,
                () -> PairingPrivateKey.fromBytes(invalidKey2),
                "Invalid key should throw an exception");

        assertEquals(
                sk,
                PairingPrivateKey.fromBytes(sk.toBytes()),
                "Should be able to obtain the same key from its byte array representation");
        assertEquals(
                pk,
                PairingPublicKey.fromBytes(pk.toBytes()),
                "Should be able to obtain the same key from its byte array representation");
        assertThrows(
                IllegalArgumentException.class,
                () -> PairingPublicKey.fromBytes(invalidKey),
                "Invalid key should throw an exception");
        assertThrows(
                IllegalArgumentException.class,
                () -> PairingPublicKey.fromBytes(invalidKey2),
                "Invalid key should throw an exception");

        flipEachBitAndDo(
                sk.toBytes(),
                val -> assertThrows(
                        IllegalArgumentException.class,
                        () -> PairingPublicKey.fromBytes(val),
                        "Invalid key should throw an exception"));
        flipEachBitAndDo(
                pk.toBytes(),
                val -> assertThrows(
                        IllegalArgumentException.class,
                        () -> PairingPublicKey.fromBytes(val),
                        "Invalid key should throw an exception"));
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
                val -> assertThrows(
                        IllegalArgumentException.class,
                        () -> PairingSignature.fromBytes(val),
                        "Invalid signature should throw an exception"));

        assertEquals(
                signature,
                PairingSignature.fromBytes(signature.toBytes()),
                "Should be able to obtain the same signature from its byte array representation");

        final byte[] invalidSignature = new byte[0];
        final byte[] invalidSignature2 = new byte[] {schema.getIdByte(), 0, 0, 0, 0};
        assertThrows(
                IllegalArgumentException.class,
                () -> PairingSignature.fromBytes(invalidSignature),
                "Invalid signature should throw an exception");
        assertThrows(
                IllegalArgumentException.class,
                () -> PairingSignature.fromBytes(invalidSignature2),
                "Invalid signature should throw an exception");
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
