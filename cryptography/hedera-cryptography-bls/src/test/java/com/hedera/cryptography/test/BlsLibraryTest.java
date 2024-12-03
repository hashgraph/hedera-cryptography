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

package com.hedera.cryptography.test;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.bls.BlsKeyPair;
import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.BlsSignature;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.bls.extensions.serialization.DefaultBlsPrivateKeySerialization;
import com.hedera.cryptography.bls.extensions.serialization.DefaultBlsPublicKeySerialization;
import com.hedera.cryptography.bls.extensions.serialization.DefaultBlsSignatureSerialization;
import com.hedera.cryptography.bls.test.fixtures.BlsTestUtils;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.testfixtures.altbn128.AltBn128ExternalData;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import com.hedera.cryptography.utils.test.fixtures.stream.StreamUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.BitSet;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@WithRng
class BlsLibraryTest {

    private static final double DEVIATION = 0.05;
    private static final int POPULATION_SIZE = 256;
    public static final String MESSAGE = "Flipped bytes should be an invalid or different key";

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @DisplayName(
            "Derive the public key multiple times from the same private key and verify that the results are consistently the same")
    void testKeyConsistency(SignatureSchema schema, final Random rng) {
        final var sk = BlsPrivateKey.create(schema, rng);
        assertNotNull(sk);
        assertNotNull(sk.createPublicKey());
        final var pk = sk.createPublicKey();
        assertEquals(pk, sk.createPublicKey(), "public key should be deterministic");
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @DisplayName("Generate multiple private keys and ensure that keys are not repeated and appear random")
    void testRandomness(SignatureSchema schema, final Random rng) {
        final var keys = rng.longs(10000)
                .mapToObj(i -> BlsPrivateKey.create(schema, rng))
                .collect(Collectors.toSet());

        assertTrue(keys.size() > 9999);
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @DisplayName("detect incorrectly used pseudorandom number generators in privateKeys")
    void testRandomnessSinglePrivateKeyByteDistribution(SignatureSchema schema, final Random rng) {
        final var key = BlsPrivateKey.create(schema, rng);
        final var keyBytes = DefaultBlsPrivateKeySerialization.getSerializer().serialize(key);
        assertDistribution(keyBytes); // Allow a 5% deviation
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @DisplayName("Generate multiple public keys and ensure that keys are not repeated and appear random")
    void testRandomnessPublicKeys(SignatureSchema schema, final Random rng) {
        final var keys = rng.longs(10000)
                .mapToObj(i -> BlsPrivateKey.create(schema, rng).createPublicKey())
                .collect(Collectors.toSet());

        assertTrue(keys.size() > 9999);
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @DisplayName("detect incorrectly used pseudorandom number generators in privateKeys")
    void testRandomnessSinglePublicKeyByteDistribution(SignatureSchema schema, final Random rng) {
        final var key = BlsPrivateKey.create(schema, rng).createPublicKey();
        final var keyBytes = DefaultBlsPublicKeySerialization.getSerializer().serialize(key);
        assertDistribution(keyBytes); // Allow a 5% deviation
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @DisplayName("ensure signatures vary given the same signing keys and different signing messages")
    void testRandomnessSignaturesMessages(SignatureSchema schema, final Random rng) {

        final var sk = BlsPrivateKey.create(schema, rng);

        final var messages = rng.longs(10000)
                .mapToObj(i -> new byte[32])
                .peek(rng::nextBytes)
                .toList();

        final var signatures = messages.stream().map(sk::sign).collect(Collectors.toSet());

        assertEquals(new HashSet<>(signatures).size(), signatures.size());
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @DisplayName("For known private keys, check that the derived public key matches the expected values.")
    void test(SignatureSchema schema) {
        final var externalData = new AltBn128ExternalData();
        final var sks = externalData.getScalars().stream()
                .map(schema.getPairingFriendlyCurve().field()::fromBigInteger)
                .map(element -> new BlsPrivateKey(element, schema))
                .toList();

        final var derivatedpks =
                sks.stream().map(element -> element.createPublicKey().element()).toList();
        final var pksValues = schema.getGroupAssignment() == GroupAssignment.SHORT_SIGNATURES
                ? externalData.getG2Points()
                : externalData.getG1Points();

        final var pks = pksValues.stream()
                .map(l -> schema.getPublicKeyGroup().fromCoordinates(List.of(l.getFirst()), List.of(l.getLast())))
                .toList();

        StreamUtils.zipStream(pks, derivatedpks).forEach(e -> assertEquals(e.getKey(), e.getValue()));
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @DisplayName("ensure signatures vary given the same input message and different signing keys")
    void testRandomnessSignaturesKeys(SignatureSchema schema, final Random rng) {

        final var keys = rng.longs(10000)
                .mapToObj(i -> BlsPrivateKey.create(schema, rng))
                .collect(Collectors.toSet());

        final var message = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);
        final var signatures = keys.stream().map(sk -> sk.sign(message)).collect(Collectors.toSet());

        assertEquals(new HashSet<>(keys).size(), signatures.size());
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @SuppressWarnings("ConstantConditions")
    @DisplayName("Attempt to generate private keys with invalid parameters and expect proper error handling")
    void testInvalidGenerationPrivateKeys(SignatureSchema schema, final Random rng) {
        final byte[] invalidKey = new byte[0];
        assertThrows(
                NullPointerException.class,
                () -> BlsPrivateKey.create(null, rng),
                "Invalid key should throw an exception");

        assertThrows(
                NullPointerException.class,
                () -> BlsPrivateKey.create(schema, null),
                "Invalid key should throw an exception");

        final var deserializer = DefaultBlsPrivateKeySerialization.getDeserializer(schema);
        assertThrows(
                IllegalStateException.class,
                () -> deserializer.deserialize(invalidKey),
                "Invalid key should throw an exception");
        final byte[] invalidKey2 = new byte[] {0, 0, 0, 0};
        assertThrows(
                IllegalStateException.class,
                () -> deserializer.deserialize(invalidKey2),
                "Invalid key should throw an exception");
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @SuppressWarnings("ConstantConditions")
    @DisplayName("Attempt to generate public keys with invalid parameters and expect proper error handling")
    void testInvalidGenerationPublicKeys(SignatureSchema schema, final Random rng) {
        final byte[] invalidKey = new byte[0];
        assertThrows(
                NullPointerException.class,
                () -> new BlsPublicKey(null, schema),
                "Invalid key should throw an exception");

        assertThrows(
                NullPointerException.class,
                () -> new BlsPublicKey(schema.getPublicKeyGroup().random(rng), null),
                "Invalid key should throw an exception");

        assertThrows(
                IllegalStateException.class,
                () -> DefaultBlsPublicKeySerialization.getDeserializer(schema).deserialize(invalidKey),
                "Invalid key should throw an exception");
        final byte[] invalidKey2 = new byte[] {0, 0, 0, 0};
        assertThrows(
                IllegalStateException.class,
                () -> DefaultBlsPublicKeySerialization.getDeserializer(schema).deserialize(invalidKey2),
                "Invalid key should throw an exception");
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @SuppressWarnings("ConstantConditions")
    @DisplayName("Attempt to generate signatures with invalid parameters and expect proper error handling")
    void testInvalidGenerationSignatures(SignatureSchema schema, final Random rng) {
        final byte[] invalidSignature = new byte[0];
        assertThrows(
                NullPointerException.class,
                () -> new BlsSignature(null, schema),
                "Invalid signature should throw an exception");

        assertThrows(
                NullPointerException.class,
                () -> new BlsPublicKey(schema.getSignatureGroup().random(rng), null),
                "Invalid signature should throw an exception");

        assertThrows(
                IllegalStateException.class,
                () -> DefaultBlsSignatureSerialization.getDeserializer(schema).deserialize(invalidSignature),
                "Invalid signature should throw an exception");
        final byte[] invalidKey2 = new byte[] {0, 0, 0, 0};
        assertThrows(
                IllegalStateException.class,
                () -> DefaultBlsSignatureSerialization.getDeserializer(schema).deserialize(invalidKey2),
                "Invalid signature should throw an exception");
    }

    @Test
    void privateKeySerializationTest(final Random rng) {
        final var schema = SignatureSchema.create(
                Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES); // we dont care about the assignament for filds
        final var sk = BlsPrivateKey.create(schema, rng);
        final var serializer = DefaultBlsPrivateKeySerialization.getSerializer();
        final var deserializer = DefaultBlsPrivateKeySerialization.getDeserializer(schema);

        assertEquals(
                sk,
                deserializer.deserialize(serializer.serialize(sk)),
                "Should be able to obtain the same key from its byte array representation");
    }

    @Test
    @DisplayName(
            "Modify a valid privateKey slightly (i.e., change a single byte) and check that it is rejected or is not the same key.")
    void privateKeyFlipTest(final Random rng) {
        final var schema = SignatureSchema.create(
                Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES); // we dont care about the assignament for filds
        final var serializer = DefaultBlsPrivateKeySerialization.getSerializer();
        final var deserializer = DefaultBlsPrivateKeySerialization.getDeserializer(schema);
        final var sk = BlsPrivateKey.create(schema, rng);
        flipEachBitAndConsume(serializer.serialize(sk), exceptionOrDifferentExpected(sk, deserializer));
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    @DisplayName(
            "Modify a valid publicKey slightly (i.e., change a single byte) and check that it is rejected or is not the same key.")
    void publicKeyFlipTest(SignatureSchema schema, final Random rng) {
        final var sk = BlsPrivateKey.create(schema, rng);
        final var pk = sk.createPublicKey();
        final var serializer = DefaultBlsPublicKeySerialization.getSerializer();
        final var deserializer = DefaultBlsPublicKeySerialization.getDeserializer(schema);

        flipEachBitAndConsume(serializer.serialize(pk), exceptionOrDifferentExpected(pk, deserializer));
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void signatureFlipTest(SignatureSchema schema, final Random rng) {
        final var sk = BlsPrivateKey.create(schema, rng);
        final var pk = sk.createPublicKey();
        final var message = "A signature".getBytes(StandardCharsets.UTF_8);
        final var signature = sk.sign(message);
        final var serializer = DefaultBlsSignatureSerialization.getSerializer();
        final var deserializer = DefaultBlsSignatureSerialization.getDeserializer(schema);

        flipEachBitAndConsume(serializer.serialize(signature), exceptionOrDifferentExpected(signature, deserializer));

        flipEachBitAndConsume(serializer.serialize(signature), signatureFlippedBytes -> {
            try {
                // If we did not get an exception, the value should be at least not verifiable against the public key
                assertFalse(
                        pk.verifySignature(signatureFlippedBytes, message), "Invalid signature should be identified");
            } catch (Exception e) {
                assertEquals(IllegalArgumentException.class, e.getClass(), "Invalid signature should be identified");
            }
        });
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void verifySignatureTest(SignatureSchema schema, final Random rng) {
        final var sk = BlsPrivateKey.create(schema, rng);

        var message = new byte[POPULATION_SIZE];
        rng.nextBytes(message);

        final var signature = sk.sign(message);
        assertNotNull(signature);
        assertEquals(signature, sk.sign(message));

        final BlsPublicKey publicKey = sk.createPublicKey();
        assertTrue(signature.verify(publicKey, message), "signature should be valid");

        IntStream.range(0, POPULATION_SIZE).forEach(i -> {
            final var pk2 = BlsPrivateKey.create(schema, rng);
            assertFalse(
                    signature.verify(pk2.createPublicKey(), message),
                    "No other public key should verify the signature");
        });
    }

    @Test
    @DisplayName("Keys and signatures can be aggregated, the aggregated key verifies the aggregated signature")
    void blsAggregationTest(final Random random) {
        final var schema = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS);
        final var pairs = BlsTestUtils.generateKeyPairs(random, schema, 4);

        final var msg =
                """
                    From Wikipedia, the free encyclopedia
                    This article is about plants in the family Araliaceae. For the typographic ornamentation ❧, see Fleuron (typography). For Hedera Hashgraph, see Hashgraph.
                    "Ivy" redirects here. For other plants, see list of plants known as ivy. For other uses, see Ivy (disambiguation).
                    Not to be confused with Hadera.
                    Hedera, commonly called ivy (plural ivies), is a genus of 12–15 species of evergreen climbing or ground-creeping woody plants in the family Araliaceae, native to Western Europe, Central Europe, Southern Europe, Macaronesia, northwestern Africa and across central-southern Asia east to Japan and Taiwan. Several species are cultivated as climbing ornamentals, and the name ivy especially denotes common ivy (Hedera helix), known in North America as "English ivy", which is frequently planted to clothe brick walls.
                    """
                        .getBytes(StandardCharsets.UTF_8);

        final var signatures = BlsTestUtils.bulkSign(pairs, msg);
        final var publicKeys = pairs.stream().map(BlsKeyPair::publicKey).toList();
        for (int i = 0; i < signatures.size(); i++) {
            final var signature = signatures.get(i);
            final var publicKey = publicKeys.get(i);
            assertTrue(signature.verify(publicKey, msg));
        }

        final var aggregatedPk = BlsPublicKey.aggregate(publicKeys);
        final var aggregateSignature = BlsSignature.aggregate(signatures);
        assertTrue(aggregateSignature.verify(aggregatedPk, msg));
    }

    /**
     *  Asserts that either throws an IllegalArgumentException or that the result of invoking the consumer is not the same as the original value
     *
     * @param originalValue expected value to be different from this one
     * @param creator the function that creates the elements from an array
     * @param <T> the type of the comparison object
     * @return a consumer that performs the check when requested
     */
    private <T> Consumer<byte[]> exceptionOrDifferentExpected(
            final T originalValue, final Function<byte[], T> creator) {
        return bytes -> {
            try {
                // If we did not get an exception, the value should be at least different than the original
                assertNotEquals(originalValue, creator.apply(bytes), MESSAGE);
            } catch (Exception e) {
                assertEquals(IllegalStateException.class, e.getClass(), MESSAGE);
            }
        };
    }

    /**
     * Flip each bit of a byte original and invoke the consumer on each flip.
     * @param original the original with where the flipping will occur. The original is modified
     * @param consumer the consumer to invoke on each flip
     */
    public static void flipEachBitAndConsume(@NonNull final byte[] original, final @NonNull Consumer<byte[]> consumer) {
        final BitSet bitSet = BitSet.valueOf(original);

        for (int i = 0; i < original.length; i++) {
            for (int bitPosition = 0; bitPosition < 8; bitPosition++) {
                bitSet.flip(i * bitPosition);
                consumer.accept(bitSet.toByteArray());
                bitSet.flip(i * bitPosition);
            }
        }
    }

    private static Stream<SignatureSchema> combinedParameters() {
        return Arrays.stream(GroupAssignment.values()).map(v -> SignatureSchema.create(Curve.ALT_BN128, v));
    }

    private static void assertDistribution(final byte[] keyBytes) {
        final int[] frequencies = new int[POPULATION_SIZE];
        for (byte b : keyBytes) {
            frequencies[Byte.toUnsignedInt(b)]++;
        }
        double tolerance = POPULATION_SIZE * DEVIATION;
        for (byte b : keyBytes) {
            assertTrue(
                    frequencies[Byte.toUnsignedInt(b)] <= tolerance,
                    "Frequency " + frequencies[Byte.toUnsignedInt(b)] + " deviates too much from the expected "
                            + tolerance);
        }
    }
}
