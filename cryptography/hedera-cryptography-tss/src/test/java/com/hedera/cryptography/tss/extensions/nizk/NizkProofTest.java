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

package com.hedera.cryptography.tss.extensions.nizk;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.extensions.EcPolynomial;
import com.hedera.cryptography.tss.api.TssShareTable;
import com.hedera.cryptography.tss.extensions.Shamir;
import com.hedera.cryptography.tss.extensions.elgamal.ElGamalUtils;
import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

public class NizkProofTest {
    static final Random INIT_RANDOM = new SecureRandom();
    static final SignatureSchema schema = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);

    @Test
    public void proof() {

        final var random = new Random(INIT_RANDOM.nextInt());
        final var field = schema.getPairingFriendlyCurve().field();
        final var group = schema.getPublicKeyGroup();

        final var secret = field.fromLong(42);
        final var numParticipants = 19;
        final var threshold = 4;

        final var ids = IntStream.range(1, numParticipants + 1).boxed().toList();
        final var privateKeys =
                ids.stream().map(i -> BlsPrivateKey.create(schema, random)).toList();
        final var publicKeys =
                privateKeys.stream().map(BlsPrivateKey::createPublicKey).toList();
        final TssShareTable<BlsPublicKey> elGamalEncryptionKeys = share -> publicKeys.get(share - 1);

        // A d degree polynomial is defined by d + 1 coefficients: a_0, a_1, ..., a_d
        // such that p(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_d * x^d
        // here we want d = threshold - 1, so threshold of points can identify this polynomial
        final var polynomial = Shamir.interpolationPolynomial(random, secret, threshold - 1);
        final var secrets = ids.stream().map(polynomial::evaluate).toList();

        final var entropy = ElGamalUtils.generateEntropy(random, field.elementSize(), schema);
        final var cipherTable = ElGamalUtils.ciphertextTable(schema, entropy, elGamalEncryptionKeys, secrets);
        final var combinedCipher = cipherTable.combine(field.fromLong(ElGamalUtils.TOTAL_NUMBER_OF_ELEMENTS));
        final var polyCommitment = Shamir.feldmanCommitment(group, polynomial);
        final var statement = new NizkStatement(ids, elGamalEncryptionKeys, polyCommitment, combinedCipher);
        final var witness = NizkWitness.create(entropy, secrets);
        final var proof = NizkProof.prove(schema, random, statement, witness);
        // The verification of the same statement should be correct
        assertTrue(proof.verify(schema, statement));
        // The verification of a different statement should be incorrect

        // Try wrong public keys
        final var elGamalEncryptionWrongKeys = IntStream.range(0, ids.size())
                .boxed()
                .map(i -> new BlsPublicKey(group.generator().multiply(field.fromLong(i)), schema))
                .toList();
        final TssShareTable<BlsPublicKey> wrongTssEncryptionKeyResolver =
                tssShareId -> elGamalEncryptionWrongKeys.get(tssShareId - 1);
        assertFalse(proof.verify(
                schema, new NizkStatement(ids, wrongTssEncryptionKeyResolver, polyCommitment, combinedCipher)));
        // Try wrong commitment
        final var wrongCommitmentCoefficients = polyCommitment.coefficients().stream()
                .map(e -> e.add(group.generator()))
                .toList();
        final var wrongCommitment = new EcPolynomial(wrongCommitmentCoefficients);
        assertFalse(
                proof.verify(schema, new NizkStatement(ids, elGamalEncryptionKeys, wrongCommitment, combinedCipher)));
        // Try wrong combinedCipher
        final var wrongCipherTable =
                ElGamalUtils.ciphertextTable(schema, entropy, wrongTssEncryptionKeyResolver, secrets);
        final var wrongCombinedCipher = wrongCipherTable.combine(field.fromLong(ElGamalUtils.TOTAL_NUMBER_OF_ELEMENTS));
        assertFalse(proof.verify(
                schema, new NizkStatement(ids, elGamalEncryptionKeys, wrongCommitment, wrongCombinedCipher)));
    }
}
