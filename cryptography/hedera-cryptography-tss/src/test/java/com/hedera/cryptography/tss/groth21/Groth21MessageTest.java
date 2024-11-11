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
import com.hedera.cryptography.tss.api.TssShareTable;
import com.hedera.cryptography.tss.extensions.elgamal.CombinedCiphertext;
import com.hedera.cryptography.tss.extensions.nizk.NizkStatement;
import com.hedera.cryptography.tss.test.fixtures.TssTestUtils;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
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

    @Test
    void testInvalidVersion() {
        final var tssMessage = TssTestUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        final var bytes = tssMessage.toBytes();
        // Corrupt the version bytes
        bytes[0] = (byte) 0xFF;
        bytes[1] = (byte) 0xFF;
        bytes[2] = (byte) 0xFF;
        bytes[3] = (byte) 0xFF;

        assertThrows(IllegalStateException.class, () -> Groth21Message.fromBytes(bytes, SIGNATURE_SCHEMA));
    }

    @Test
    void testDifferentSignatureSchema() {
        final var tssMessage = TssTestUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        final var bytes = tssMessage.toBytes();

        assertThrows(
                IllegalStateException.class,
                () -> Groth21Message.fromBytes(
                        bytes, SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS)));
    }

    @Test
    void testInvalidSignatureSchema() {
        final var tssMessage = TssTestUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        final var bytes = tssMessage.toBytes();
        // Set an invalid signature schema byte
        bytes[Integer.BYTES] = (byte) 0xFF;

        assertThrows(IllegalStateException.class, () -> Groth21Message.fromBytes(bytes, SIGNATURE_SCHEMA));
    }

    @Test
    void testInvalidShorterMessageLength(Random rand) {
        var tssMessage = TssTestUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        byte[] bytes = new byte[rand.nextInt(0, tssMessage.toBytes().length)];
        rand.nextBytes(bytes);
        assertThrows(IllegalStateException.class, () -> Groth21Message.fromBytes(bytes, SIGNATURE_SCHEMA));
    }

    @Test
    void testValidLargerMessageLength(Random rand) {
        final var tssMessage = TssTestUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        final var validMessageBytes = tssMessage.toBytes();
        final var bytes = new byte[validMessageBytes.length + rand.nextInt(1, validMessageBytes.length)];
        System.arraycopy(validMessageBytes, 0, bytes, 0, validMessageBytes.length);

        final var statement = validStatement();

        assertTrue(Groth21Message.fromBytes(bytes, SIGNATURE_SCHEMA).proof().verify(SIGNATURE_SCHEMA, statement));
    }

    @Test
    void fromToBytes() {
        var tssMessage = TssTestUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        final Groth21Message actual = Groth21Message.fromBytes(tssMessage.toBytes(), SIGNATURE_SCHEMA);
        assertNotNull(actual);
        assertEquals(0, actual.generatingShare());
        assertEquals(2, actual.cipherTable().shareCiphertexts().length);
        final NizkStatement statement = validStatement();
        assertTrue(actual.proof().verify(SIGNATURE_SCHEMA, statement));
    }

    @Test
    void testToToBytes() {
        final var tssMessage = TssTestUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        final var actual = Groth21Message.fromBytes(
                Groth21Message.fromBytes(tssMessage.toBytes(), SIGNATURE_SCHEMA).toBytes(), SIGNATURE_SCHEMA);
        assertNotNull(actual);
        assertNotSame(actual, tssMessage);
        assertEquals(0, actual.generatingShare());
        assertEquals(2, actual.cipherTable().shareCiphertexts().length);
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
