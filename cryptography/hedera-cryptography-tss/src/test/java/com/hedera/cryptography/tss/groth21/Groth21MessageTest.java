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

package com.hedera.cryptography.tss.groth21;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.extensions.EcPolynomial;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssShareTable;
import com.hedera.cryptography.tss.extensions.serialization.TssMessageDeserializers;
import com.hedera.cryptography.tss.extensions.serialization.TssMessageSerializers;
import com.hedera.cryptography.tss.impl.elgamal.CombinedCiphertext;
import com.hedera.cryptography.tss.impl.groth21.Groth21Message;
import com.hedera.cryptography.tss.impl.nizk.NizkStatement;
import com.hedera.cryptography.tss.test.fixtures.TssTestCommittee;
import com.hedera.cryptography.tss.test.fixtures.TssTestUtils;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

@WithRng
class Groth21MessageTest {

    static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);
    static final GroupElement ZERO = SIGNATURE_SCHEMA.getPublicKeyGroup().zero();
    static final TssShareTable<BlsPublicKey> TABLE = shareId -> new BlsPublicKey(ZERO, SIGNATURE_SCHEMA);
    static final TssParticipantDirectory DIR =
            new TssTestCommittee(3, 1, TssTestUtils.rndSks(SIGNATURE_SCHEMA, new Random(), 3)).participantDirectory();
    static final TssMessage tssMessage = TssTestUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 3, 2);

    @Test
    void testInvalidVersion() {
        final var bytes =
                TssMessageSerializers.defaultSerializer(SIGNATURE_SCHEMA).serialize(tssMessage);
        // Corrupt the version bytes
        bytes[0] = (byte) 0xFF;
        bytes[1] = (byte) 0xFF;
        bytes[2] = (byte) 0xFF;
        bytes[3] = (byte) 0xFF;

        assertThrows(
                IllegalStateException.class, () -> TssMessageDeserializers.defaultDeserializer(SIGNATURE_SCHEMA, DIR)
                        .deserialize(bytes));
    }

    @Test
    void testDifferentSignatureSchema() {
        final var bytes =
                TssMessageSerializers.defaultSerializer(SIGNATURE_SCHEMA).serialize(tssMessage);

        assertThrows(
                IllegalStateException.class,
                () -> Groth21Message.fromBytes(
                        bytes, DIR, SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS)));
    }

    @Test
    void testInvalidSignatureSchema() {
        final var bytes =
                TssMessageSerializers.defaultSerializer(SIGNATURE_SCHEMA).serialize(tssMessage);
        // Set an invalid signature schema byte
        bytes[Integer.BYTES] = (byte) 0xFF;

        assertThrows(
                IllegalStateException.class, () -> TssMessageDeserializers.defaultDeserializer(SIGNATURE_SCHEMA, DIR)
                        .deserialize(bytes));
    }

    @Test
    void testCorruptedMessage() {
        final var bytes =
                TssMessageSerializers.defaultSerializer(SIGNATURE_SCHEMA).serialize(tssMessage);
        var headerEnd = 4 + 1 + 4;
        Arrays.fill(bytes, headerEnd, bytes.length, (byte) -1);
        assertThrows(
                IllegalStateException.class, () -> TssMessageDeserializers.defaultDeserializer(SIGNATURE_SCHEMA, DIR)
                        .deserialize(bytes));
    }

    @Test
    void testInvalidRandomness() {
        final var bytes =
                TssMessageSerializers.defaultSerializer(SIGNATURE_SCHEMA).serialize(tssMessage);

        // Set an invalid List size
        var headerEnd = 4 + 1 + 4;
        var value = SIGNATURE_SCHEMA.getPublicKeyGroup().elementSize()
                * SIGNATURE_SCHEMA.getPairingFriendlyCurve().field().elementSize();
        Arrays.fill(bytes, headerEnd, value, Byte.MAX_VALUE);
        assertThrows(
                IllegalStateException.class, () -> TssMessageDeserializers.defaultDeserializer(SIGNATURE_SCHEMA, DIR)
                        .deserialize(bytes));
    }

    @Test
    void testInvalidShorterMessageLength(Random rand) {
        byte[] bytes = new byte
                [rand.nextInt(
                        0,
                        TssMessageSerializers.defaultSerializer(SIGNATURE_SCHEMA)
                                .serialize(tssMessage)
                                .length)];
        rand.nextBytes(bytes);
        assertThrows(
                IllegalStateException.class, () -> TssMessageDeserializers.defaultDeserializer(SIGNATURE_SCHEMA, DIR)
                        .deserialize(bytes));
    }

    @Test
    void testInvalidLargerMessageLength(Random rand) {
        final var messageBytes =
                TssMessageSerializers.defaultSerializer(SIGNATURE_SCHEMA).serialize(tssMessage);
        final var bytes = new byte[messageBytes.length + rand.nextInt(1, messageBytes.length)];
        System.arraycopy(messageBytes, 0, bytes, 0, messageBytes.length);
        assertThrows(
                IllegalStateException.class, () -> TssMessageDeserializers.defaultDeserializer(SIGNATURE_SCHEMA, DIR)
                        .deserialize(bytes));
    }

    @Test
    void fromToBytes() {
        final var messageBytes =
                TssMessageSerializers.defaultSerializer(SIGNATURE_SCHEMA).serialize(tssMessage);
        final Groth21Message actual = TssMessageDeserializers.<Groth21Message>defaultDeserializer(SIGNATURE_SCHEMA, DIR)
                .deserialize(messageBytes);
        assertNotNull(actual);
        assertEquals(0, actual.generatingShare());
        assertEquals(3, actual.cipherTable().shareCiphertexts().length);
        final NizkStatement statement = validStatement();
        assertTrue(actual.proof().verify(SIGNATURE_SCHEMA, statement));
    }

    @Test
    void testToToBytes() {
        final var m1 = TssMessageSerializers.defaultSerializer(SIGNATURE_SCHEMA).serialize(tssMessage);
        final var m2 = TssMessageDeserializers.<Groth21Message>defaultDeserializer(SIGNATURE_SCHEMA, DIR)
                .deserialize(m1);
        var m3 = TssMessageSerializers.defaultSerializer(SIGNATURE_SCHEMA).serialize(m2);
        assertArrayEquals(m1, m3);
        final var actual = TssMessageDeserializers.<Groth21Message>defaultDeserializer(SIGNATURE_SCHEMA, DIR)
                .deserialize(m3);
        assertNotNull(actual);
        assertNotSame(tssMessage, actual);
        assertEquals(0, actual.generatingShare());
        assertEquals(3, actual.cipherTable().shareCiphertexts().length);
        final NizkStatement statement = validStatement();
        assertTrue(actual.proof().verify(SIGNATURE_SCHEMA, statement));
    }

    @Test
    void fromToBytesCompressed() {
        final var messageBytes =
                TssMessageSerializers.compressedSerializer(SIGNATURE_SCHEMA).serialize(tssMessage);
        final Groth21Message actual = TssMessageDeserializers.<Groth21Message>compressedDeserializer(
                        SIGNATURE_SCHEMA, DIR)
                .deserialize(messageBytes);
        assertNotNull(actual);
        assertEquals(0, actual.generatingShare());
        assertEquals(3, actual.cipherTable().shareCiphertexts().length);
        final NizkStatement statement = validStatement();
        assertTrue(actual.proof().verify(SIGNATURE_SCHEMA, statement));
    }

    private static NizkStatement validStatement() {
        return new NizkStatement(
                List.of(1, 2),
                Groth21MessageTest.TABLE,
                new EcPolynomial(List.of(ZERO, ZERO)),
                new CombinedCiphertext(ZERO, Collections.nCopies(32, ZERO)));
    }
}
