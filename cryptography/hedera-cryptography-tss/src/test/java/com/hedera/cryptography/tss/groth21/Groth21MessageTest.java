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
import com.hedera.cryptography.tss.test.fixtures.DkgUtils;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

class Groth21MessageTest {

    static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);

    @Test
    void fromBytes() {
        var tssMessage = DkgUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        final Groth21Message actual = Groth21Message.fromBytes(tssMessage.bytes());
        assertNotNull(actual);
        assertEquals(0, actual.generatingShare());
        assertEquals(2, actual.cipherTable().shareCiphertexts().length);
        final GroupElement zero = SIGNATURE_SCHEMA.getPublicKeyGroup().zero();
        TssShareTable<BlsPublicKey> table = shareId -> new BlsPublicKey(zero, SIGNATURE_SCHEMA);
        final NizkStatement statement = new NizkStatement(
                List.of(1, 2),
                table,
                new EcPolynomial(List.of(zero, zero)),
                new CombinedCiphertext(zero, Collections.nCopies(32, zero)));
        assertTrue(actual.proof().verify(SIGNATURE_SCHEMA, statement));
    }

    @Test
    void fromTssMessage() {
        var tssMessage = DkgUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        final Groth21Message actual = Groth21Message.fromTssMessage(tssMessage);
        assertNotNull(actual);
        assertNotSame(actual, tssMessage);
        assertEquals(0, actual.generatingShare());
        assertEquals(2, actual.cipherTable().shareCiphertexts().length);
        final GroupElement zero = SIGNATURE_SCHEMA.getPublicKeyGroup().zero();
        TssShareTable<BlsPublicKey> table = shareId -> new BlsPublicKey(zero, SIGNATURE_SCHEMA);
        final NizkStatement statement = new NizkStatement(
                List.of(1, 2),
                table,
                new EcPolynomial(List.of(zero, zero)),
                new CombinedCiphertext(zero, Collections.nCopies(32, zero)));
        assertTrue(actual.proof().verify(SIGNATURE_SCHEMA, statement));
    }

    @Test
    void fromTssMessageReturnsSameInstance() {
        var tssMessage = DkgUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        final Groth21Message actual = Groth21Message.fromTssMessage(tssMessage);
        assertSame(actual, Groth21Message.fromTssMessage(actual));
    }

    @Test
    void toBytes() {
        var tssMessage = DkgUtils.testTssMessage(SIGNATURE_SCHEMA, 0, 2, 3);
        final Groth21Message actual = Groth21Message.fromBytes(
                Groth21Message.fromTssMessage(tssMessage).bytes());
        assertNotNull(actual);
        assertNotSame(actual, tssMessage);
        assertEquals(0, actual.generatingShare());
        assertEquals(2, actual.cipherTable().shareCiphertexts().length);
        final GroupElement zero = SIGNATURE_SCHEMA.getPublicKeyGroup().zero();
        TssShareTable<BlsPublicKey> table = shareId -> new BlsPublicKey(zero, SIGNATURE_SCHEMA);
        final NizkStatement statement = new NizkStatement(
                List.of(1, 2),
                table,
                new EcPolynomial(List.of(zero, zero)),
                new CombinedCiphertext(zero, Collections.nCopies(32, zero)));
        assertTrue(actual.proof().verify(SIGNATURE_SCHEMA, statement));
    }
}
