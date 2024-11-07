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

package com.hedera.cryptography.tss.extensions.elgamal;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.*;
import com.hedera.cryptography.tss.api.TssShareTable;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
@WithRng
public class ElGamalUtilsTest {
    static final SignatureSchema schema = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS);

    @RepeatedTest(100)
    public void testCompleteOperation(final Random random) {
        final BlsPrivateKey sk = BlsPrivateKey.create(schema, random);
        final BlsPublicKey pk = sk.createPublicKey();
        final ElGamalSubstitutionTable<FieldElement, Byte> substitutionTable =
                ElGamalUtils.elGamalSubstitutionTable(schema);

        final var secret = schema.getPairingFriendlyCurve().field().random(random);
        final var entropy = ElGamalUtils.generateEntropy(random, secret.size(), schema);
        final var encryptedCipher = ElGamalUtils.createCipherText(pk, substitutionTable, entropy, secret.toBytes());

        assertNotNull(encryptedCipher);
        assertEquals(schema.getPairingFriendlyCurve().field().elementSize(), encryptedCipher.size());

        var reverseTable = ElGamalUtils.elGamalReverseSubstitutionTable(schema);
        var entropy2 = entropy.stream()
                .map(e -> schema.getPublicKeyGroup().generator().multiply(e))
                .toList();
        var recoveredSecret = ElGamalUtils.readCipherText(sk, entropy2, reverseTable, encryptedCipher);

        assertNotNull(recoveredSecret);
        assertEquals(secret, schema.getPairingFriendlyCurve().field().fromBytes(recoveredSecret));
    }

    private static final byte[] SECRET = new byte[] {
        31, 4, 1, 5, 92, 65, 35, 89, 79, 32, 38, 46, 26, 43, 38, 32, 79, 50, 28, 8, 41, 9, 71, 69, 39, 93, 75, 105, 8,
        20, 97, 49
    };

    @Test
    public void invalidKeyCannotRecoverTheSecret(final Random random) {
        final BlsPrivateKey sk = BlsPrivateKey.create(schema, random);
        final BlsPublicKey pk = sk.createPublicKey();
        final ElGamalSubstitutionTable<FieldElement, Byte> substitutionTable =
                ElGamalUtils.elGamalSubstitutionTable(schema);

        final var secret = schema.getPairingFriendlyCurve().field().fromBytes(SECRET);
        final var entropy = ElGamalUtils.generateEntropy(random, secret.size(), schema);
        final var encryptedCipher = ElGamalUtils.createCipherText(pk, substitutionTable, entropy, secret.toBytes());

        assertNotNull(encryptedCipher);
        assertEquals(schema.getPairingFriendlyCurve().field().elementSize(), encryptedCipher.size());

        final BlsPrivateKey sk1 = BlsPrivateKey.create(schema, random);
        var reverseTable = ElGamalUtils.elGamalReverseSubstitutionTable(schema);
        var entropy2 = entropy.stream()
                .map(e -> schema.getPublicKeyGroup().generator().multiply(e))
                .toList();

        var recoveredSecret = ElGamalUtils.readCipherText(sk1, entropy2, reverseTable, encryptedCipher);
        assertTrue(recoveredSecret == null
                || !secret.equals(schema.getPairingFriendlyCurve().field().fromBytes(recoveredSecret)));
    }

    @Test
    public void invalidRandomnessCannotRecoverTheSecret(final Random random) {
        final BlsPrivateKey sk = BlsPrivateKey.create(schema, random);
        final BlsPublicKey pk = sk.createPublicKey();
        final ElGamalSubstitutionTable<FieldElement, Byte> substitutionTable =
                ElGamalUtils.elGamalSubstitutionTable(schema);

        final var secret = schema.getPairingFriendlyCurve().field().fromBytes(SECRET);
        final var entropy = ElGamalUtils.generateEntropy(random, secret.size(), schema);
        final var encryptedCipher = ElGamalUtils.createCipherText(pk, substitutionTable, entropy, secret.toBytes());

        assertNotNull(encryptedCipher);
        assertEquals(schema.getPairingFriendlyCurve().field().elementSize(), encryptedCipher.size());

        var reverseTable = ElGamalUtils.elGamalReverseSubstitutionTable(schema);
        var entropy2 = ElGamalUtils.generateEntropy(random, secret.size(), schema).stream()
                .map(e -> schema.getPublicKeyGroup().generator().multiply(e))
                .toList();
        var recoveredSecret = ElGamalUtils.readCipherText(sk, entropy2, reverseTable, encryptedCipher);
        assertTrue(recoveredSecret == null
                || !secret.equals(schema.getPairingFriendlyCurve().field().fromBytes(recoveredSecret)));
    }

    @Test
    public void testRecoverText(final Random random) {
        final BlsPrivateKey sk = BlsPrivateKey.create(schema, random);
        final BlsPublicKey pk = sk.createPublicKey();
        final ElGamalSubstitutionTable<FieldElement, Byte> substitutionTable =
                ElGamalUtils.elGamalSubstitutionTable(schema);

        final var secret =
                """
                If you can't explain it simply, you don't understand it well enough.

                Albert Einstein
                """;

        final var entropy = ElGamalUtils.generateEntropy(random, secret.length(), schema);
        final var encryptedCipher =
                ElGamalUtils.createCipherText(pk, substitutionTable, entropy, secret.getBytes(StandardCharsets.UTF_8));

        assertNotNull(encryptedCipher);
        assertEquals(secret.length(), encryptedCipher.size());

        var reverseTable = ElGamalUtils.elGamalReverseSubstitutionTable(schema);
        var entropy2 = entropy.stream()
                .map(e -> schema.getPublicKeyGroup().generator().multiply(e))
                .toList();
        var recoveredSecret = ElGamalUtils.readCipherText(sk, entropy2, reverseTable, encryptedCipher);

        assertNotNull(recoveredSecret);
        assertEquals(secret, new String(recoveredSecret, StandardCharsets.UTF_8));
    }

    @Test
    void testCiphertextTable(final Random random) {
        final var ids = IntStream.range(1, 20).boxed().toList();
        final var field = schema.getPairingFriendlyCurve().field();
        final var secret = field.fromBytes(SECRET);
        final var sks =
                ids.stream().map(i -> BlsPrivateKey.create(schema, random)).toList();

        final var pks = sks.stream().map(BlsPrivateKey::createPublicKey).toList();
        final TssShareTable<BlsPublicKey> elGamalEncryptionKeys =
                shareId -> pks.stream().toList().get(shareId - 1);
        final var secrets = Collections.nCopies(ids.size(), secret);
        final List<FieldElement> randomness = ElGamalUtils.generateEntropy(random, field.elementSize(), schema);
        var inverse = ElGamalSubstitutionTable.inverse(schema);
        var table = ElGamalUtils.ciphertextTable(schema, randomness, elGamalEncryptionKeys, secrets);

        for (int i = 0; i < ids.size(); i++) {
            var ecVal = table.shareCiphertexts()[i];
            var dc = ElGamalUtils.readCipherText(sks.get(i), table.sharedRandomness(), inverse, ecVal);
            assertNotNull(ecVal);
            assertNotNull(dc);
            assertEquals(secret, field.fromBytes(dc));
        }
    }
}
