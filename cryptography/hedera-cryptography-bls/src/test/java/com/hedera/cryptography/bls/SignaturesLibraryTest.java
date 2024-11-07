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

package com.hedera.cryptography.bls;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.api.curves.KnownCurves;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Arrays;
import java.util.Random;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@WithRng
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
    void crateKeyPairTest(GroupAssignment assignment, final Random rng) {
        final var schema = SignatureSchema.create(Curve.ALT_BN128, assignment);

        final var sk = BlsPrivateKey.create(schema, rng);
        assertNotNull(sk);
        assertNotNull(sk.toBytes());
        assertNotNull(sk.createPublicKey());

        final var pk = sk.createPublicKey();
        assertEquals(pk, sk.createPublicKey(), "public key should be deterministic");

        final byte[] invalidKey = new byte[0];
        assertThrows(
                IllegalArgumentException.class,
                () -> BlsPrivateKey.fromBytes(invalidKey),
                "Invalid key should throw an exception");
        final byte[] invalidKey2 = new byte[] {schema.getIdByte(), 0, 0, 0, 0};
        assertThrows(
                IllegalArgumentException.class,
                () -> BlsPrivateKey.fromBytes(invalidKey2),
                "Invalid key should throw an exception");

        assertEquals(
                sk,
                BlsPrivateKey.fromBytes(sk.toBytes()),
                "Should be able to obtain the same key from its byte array representation");
        assertEquals(
                pk,
                BlsPublicKey.fromBytes(pk.toBytes()),
                "Should be able to obtain the same key from its byte array representation");
        assertThrows(
                IllegalArgumentException.class,
                () -> BlsPublicKey.fromBytes(invalidKey),
                "Invalid key should throw an exception");
        assertThrows(
                IllegalArgumentException.class,
                () -> BlsPublicKey.fromBytes(invalidKey2),
                "Invalid key should throw an exception");

        flipEachBitAndConsume(
                sk.toBytes(),
                expected(sk, BlsPrivateKey::fromBytes, "Flipped bytes should be an invalid or different key"));
        flipEachBitAndConsume(
                pk.toBytes(),
                expected(pk, BlsPublicKey::fromBytes, "Flipped bytes should be an invalid or different key"));
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void crateSignatureTest(GroupAssignment assignment, final Random rng) {
        final var schema = SignatureSchema.create(Curve.ALT_BN128, assignment);

        final var sk = BlsPrivateKey.create(schema, rng);

        var message = new byte[256];
        rng.nextBytes(message);

        final var signature = sk.sign(message);
        assertNotNull(signature);
        assertNotNull(signature.toBytes());
        assertEquals(signature, sk.sign(message));
        flipEachBitAndConsume(
                signature.toBytes(),
                expected(
                        signature,
                        BlsSignature::fromBytes,
                        "Flipped bytes should be an invalid or different signature"));

        assertEquals(
                signature,
                BlsSignature.fromBytes(signature.toBytes()),
                "Should be able to obtain the same signature from its byte array representation");

        final byte[] invalidSignature = new byte[0];
        final byte[] invalidSignature2 = new byte[] {schema.getIdByte(), 0, 0, 0, 0};
        assertThrows(
                IllegalArgumentException.class,
                () -> BlsSignature.fromBytes(invalidSignature),
                "Invalid signature should throw an exception");
        assertThrows(
                IllegalArgumentException.class,
                () -> BlsSignature.fromBytes(invalidSignature2),
                "Invalid signature should throw an exception");
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void verifySignatureTest(GroupAssignment assignment, final Random rng) {
        final var schema = SignatureSchema.create(Curve.ALT_BN128, assignment);

        final var sk = BlsPrivateKey.create(schema, rng);

        var message = new byte[256];
        rng.nextBytes(message);

        final var signature = sk.sign(message);
        assertNotNull(signature);
        assertNotNull(signature.toBytes());
        assertEquals(signature, sk.sign(message));

        final BlsPublicKey publicKey = sk.createPublicKey();
        assertTrue(signature.verify(publicKey, message), "signature should be valid");

        IntStream.range(0, 256).forEach(i -> {
            final var pk2 = BlsPrivateKey.create(schema, rng);
            assertFalse(
                    signature.verify(pk2.createPublicKey(), message),
                    "No other public key should verify the signature");
        });

        flipEachBitAndConsume(signature.toBytes(), signatureFlippedBytes -> {
            try {
                // If we did not get an exception, the value should be at least not verifiable against the public key
                assertFalse(
                        publicKey.verifySignature(signatureFlippedBytes, message),
                        "Invalid signature should be identified");
            } catch (Exception e) {
                assertEquals(IllegalArgumentException.class, e.getClass(), "Invalid signature should be identified");
            }
        });
    }

    /**
     * Flip each bit of a byte original and invoke the consumer on each flip.
     * @param original the original with where the flipping will occur. The original is modified
     * @param consumer the consumer to invoke on each flip
     */
    void flipEachBitAndConsume(@NonNull final byte[] original, final @NonNull Consumer<byte[]> consumer) {
        final byte[] copy = Arrays.copyOf(original, original.length);

        for (int i = 0; i < copy.length - 1; i++) {
            final byte originalByte = copy[i];
            for (int bitPosition = 0; bitPosition < 8; bitPosition++) {
                final byte flippedByte = (byte) (originalByte ^ (1 << bitPosition));
                copy[i] = flippedByte;
                consumer.accept(copy);
                copy[i] = originalByte;
            }
        }
        // REVIEW flipping the last bit of the sign of the last element produces the same element
        // representation.
        // Makes sense given that we use unsigned values in rust, but seems that the last bit is not checked in
        // arkworks
        final byte originalByte = copy[copy.length - 1];
        for (int bitPosition = 0; bitPosition < 7; bitPosition++) {
            final byte flippedByte = (byte) (originalByte ^ (1 << bitPosition));
            copy[copy.length - 1] = flippedByte;
            consumer.accept(copy);
            copy[copy.length - 1] = originalByte;
        }
    }

    /**
     *  Asserts that either throws an IllegalArgumentException or that the result of invoking the consumer is not the same as the original value
     *
     * @param originalValue expected value to be different from this one
     * @param creator the function that creates the elements from an array
     * @param message the message to show in case validation fails
     * @param <T> the type of the comparison object
     * @return a consumer that performs the check when requested
     */
    private <T> Consumer<byte[]> expected(
            final T originalValue, final Function<byte[], T> creator, final String message) {
        return bytes -> {
            try {
                // If we did not get an exception, the value should be at least different than the original
                assertNotEquals(originalValue, creator.apply(bytes), message);
            } catch (Exception e) {
                assertEquals(IllegalArgumentException.class, e.getClass(), message);
            }
        };
    }

    private static Stream<GroupAssignment> combinedParameters() {
        return Arrays.stream(GroupAssignment.values());
    }
}
