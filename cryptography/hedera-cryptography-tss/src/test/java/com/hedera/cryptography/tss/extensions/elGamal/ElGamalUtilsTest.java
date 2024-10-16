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

package com.hedera.cryptography.tss.extensions.elGamal;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.*;
import com.hedera.cryptography.pairings.signatures.api.GroupAssignment;
import com.hedera.cryptography.pairings.signatures.api.PairingKeyPair;
import com.hedera.cryptography.pairings.signatures.api.SignatureSchema;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

public class ElGamalUtilsTest {

    @Test
    public void testCompleteOperation() throws NoSuchAlgorithmException {
        var schema = SignatureSchema.create(
                Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS); // FUTURE TSS-Library: create a test-feature curve

        final PairingKeyPair pair = PairingKeyPair.generate(schema);
        final Map<Byte, FieldElement> substitutionTable = ElGamalUtils.elGamalSubstitutionTable(schema);

        final var random = new Random();
        final var sk = schema.getPairingFriendlyCurve().field().random(random);
        final var entropy = ElGamalUtils.generateEntropy(random, schema);
        final var encryptedCipher =
                ElGamalUtils.createCipherText(pair.publicKey(), substitutionTable, entropy, sk.toBytes());

        assertNotNull(encryptedCipher);
        assertEquals(schema.getPairingFriendlyCurve().field().elementSize(), encryptedCipher.size());

        var reverseTable = ElGamalUtils.elGamalReverseSubstitutionTable(schema);
        var entropy2 = entropy.stream()
                .map(e -> schema.getPublicKeyGroup().generator().multiply(e))
                .toList();
        var recoveredSecret = ElGamalUtils.readCipherText(pair.privateKey(), entropy2, reverseTable, encryptedCipher);

        assertNotNull(recoveredSecret);
        assertEquals(sk, schema.getPairingFriendlyCurve().field().fromBytes(recoveredSecret));
    }
}
