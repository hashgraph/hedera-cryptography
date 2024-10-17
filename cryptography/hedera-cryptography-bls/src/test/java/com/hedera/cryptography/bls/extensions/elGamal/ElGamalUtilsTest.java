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

package com.hedera.cryptography.bls.extensions.elGamal;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.*;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Random;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class ElGamalUtilsTest {
    static final Random INIT_RANDOM = new SecureRandom();

    private static Stream<Integer> randomSeeds() {
        return IntStream.range(0, 100).map(i -> INIT_RANDOM.nextInt()).boxed();
    }

    @ParameterizedTest
    @MethodSource("randomSeeds")
    public void testCompleteOperation(int seed) {
        var schema = SignatureSchema.create(
                Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS); // FUTURE TSS-Library: create a test-feature curve

        System.out.println("Seed used: " + seed);
        final Random random = new Random(seed);
        final BlsPrivateKey sk = BlsPrivateKey.create(schema, random);
        final BlsPublicKey pk = sk.createPublicKey();
        final Map<Byte, FieldElement> substitutionTable = ElGamalUtils.elGamalSubstitutionTable(schema);

        final var secret = schema.getPairingFriendlyCurve().field().random(random);
        final var entropy = ElGamalUtils.generateEntropy(random, schema);
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
    public void invalidKeyCannotRecoverTheSecret() {
        var schema = SignatureSchema.create(
                Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS); // FUTURE TSS-Library: create a test-feature curve

        var seed = INIT_RANDOM.nextLong();
        System.out.println("Seed used: " + seed);
        final Random random = new Random(seed);
        final BlsPrivateKey sk = BlsPrivateKey.create(schema, random);
        final BlsPublicKey pk = sk.createPublicKey();
        final Map<Byte, FieldElement> substitutionTable = ElGamalUtils.elGamalSubstitutionTable(schema);

        final var secret = schema.getPairingFriendlyCurve().field().fromBytes(SECRET);
        final var entropy = ElGamalUtils.generateEntropy(random, schema);
        final var encryptedCipher = ElGamalUtils.createCipherText(pk, substitutionTable, entropy, secret.toBytes());

        assertNotNull(encryptedCipher);
        assertEquals(schema.getPairingFriendlyCurve().field().elementSize(), encryptedCipher.size());

        final BlsPrivateKey sk1 = BlsPrivateKey.create(schema, random);
        var reverseTable = ElGamalUtils.elGamalReverseSubstitutionTable(schema);
        var entropy2 = entropy.stream()
                .map(e -> schema.getPublicKeyGroup().generator().multiply(e))
                .toList();
        var recoveredSecret = ElGamalUtils.readCipherText(sk1, entropy2, reverseTable, encryptedCipher);

        assertNotNull(recoveredSecret);
        assertNotEquals(secret, schema.getPairingFriendlyCurve().field().fromBytes(recoveredSecret));
    }

    @Test
    public void invalidRandomnessCannotRecoverTheSecret() {
        var schema = SignatureSchema.create(
                Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS); // FUTURE TSS-Library: create a test-feature curve

        var seed = INIT_RANDOM.nextLong();
        System.out.println("Seed used: " + seed);
        final Random random = new Random(seed);
        final BlsPrivateKey sk = BlsPrivateKey.create(schema, random);
        final BlsPublicKey pk = sk.createPublicKey();
        final Map<Byte, FieldElement> substitutionTable = ElGamalUtils.elGamalSubstitutionTable(schema);

        final var secret = schema.getPairingFriendlyCurve().field().fromBytes(SECRET);
        final var entropy = ElGamalUtils.generateEntropy(random, schema);
        final var encryptedCipher = ElGamalUtils.createCipherText(pk, substitutionTable, entropy, secret.toBytes());

        assertNotNull(encryptedCipher);
        assertEquals(schema.getPairingFriendlyCurve().field().elementSize(), encryptedCipher.size());

        var reverseTable = ElGamalUtils.elGamalReverseSubstitutionTable(schema);
        var entropy2 = ElGamalUtils.generateEntropy(random, schema).stream()
                .map(e -> schema.getPublicKeyGroup().generator().multiply(e))
                .toList();
        var recoveredSecret = ElGamalUtils.readCipherText(sk, entropy2, reverseTable, encryptedCipher);

        assertNotNull(recoveredSecret);
        assertNotEquals(secret, schema.getPairingFriendlyCurve().field().fromBytes(recoveredSecret));
    }
}
