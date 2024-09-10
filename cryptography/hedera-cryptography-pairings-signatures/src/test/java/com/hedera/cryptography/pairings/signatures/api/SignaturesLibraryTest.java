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
import java.util.function.Function;
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

        flipEachBitAndCheck(
                sk.toBytes(),
                PairingPrivateKey::fromBytes,
                IllegalArgumentException.class,
                "Flipped bytes should be an invalid or different key");
        flipEachBitAndCheck(
                pk.toBytes(),
                PairingPublicKey::fromBytes,
                IllegalArgumentException.class,
                "Flipped bytes should be an invalid or different key");
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
        flipEachBitAndCheck(
                signature.toBytes(),
                PairingSignature::fromBytes,
                IllegalArgumentException.class,
                "Flipped bytes should be an invalid or different signature");

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
     * Flip each bit of a byte original and invoke the consumer on each flip.
     * Asserts that either throws an exception or that the result of invoking the consumer is not the same as the original value
     * @param original the original with where the flipping will occur. The original is modified
     * @param consumer the consumer to invoke on each flip
     * @param throwing the expected exception
     */
    <T, E extends Throwable> void flipEachBitAndCheck(
            @NonNull final byte[] original,
            final @NonNull Function<byte[], T> consumer,
            final Class<E> throwing,
            final String message) {
        final byte[] copy = Arrays.copyOf(original, original.length);
        final T originalValue = consumer.apply(original);
        for (int i = 0; i < copy.length - 1; i++) {
            final byte originalByte = copy[i];
            for (int bitPosition = 0; bitPosition < 8; bitPosition++) {
                final byte flippedByte = (byte) (originalByte ^ (1 << bitPosition));
                copy[i] = flippedByte;
                try {
                    // If we did not get an exception, the value should be at least different than the original
                    assertNotEquals(originalValue, consumer.apply(copy), message);
                } catch (Exception e) {
                    assertEquals(throwing, e.getClass(), message);
                }
                copy[i] = originalByte;
            }
        }
        // REVIEW flipping the last bit of the sign of the last element produces the same signature
        // representation.
        // Makes sense given that we use unsigned values in rust, but seems that the last bit is not checked in
        // arkworks
        final byte originalByte = copy[copy.length - 1];
        for (int bitPosition = 0; bitPosition < 7; bitPosition++) {
            final byte flippedByte = (byte) (originalByte ^ (1 << bitPosition));
            copy[copy.length - 1] = flippedByte;
            try {
                assertNotEquals(originalValue, consumer.apply(copy), message);
            } catch (Exception e) {
                assertEquals(throwing, e.getClass(), message);
            }
            copy[copy.length - 1] = originalByte;
        }
    }

    private static Stream<GroupAssignment> combinedParameters() {
        return Arrays.stream(GroupAssignment.values());
    }
}
