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

import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.extensions.EcPolynomial;
import com.hedera.cryptography.pairings.extensions.FiniteFieldPolynomial;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.extensions.ShamirUtils;
import com.hedera.cryptography.tss.extensions.elgamal.CiphertextTable;
import com.hedera.cryptography.tss.extensions.elgamal.CombinedCiphertext;
import com.hedera.cryptography.tss.extensions.elgamal.ElGamalUtils;
import com.hedera.cryptography.tss.extensions.nizk.NizkProof;
import com.hedera.cryptography.tss.extensions.nizk.NizkStatement;
import com.hedera.cryptography.tss.extensions.nizk.NizkWitness;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.List;
import java.util.Objects;
import java.util.Random;

/**
 * All common behaviour for the between the stages implementations of TSS.
 * Contains all common code for implementing the {@link com.hedera.cryptography.tss.api.TssServiceGenesisStage}
 * or {@link com.hedera.cryptography.tss.api.TssServiceRekeyStage}
 */
public abstract class Groth21Stage {
    /**
     * defines which elliptic curve is used in the protocol, and how it's used
     */
    protected final SignatureSchema signatureSchema;
    /**
     * a random number generator
     */
    protected final Random random;

    /**
     * A Groth21Stage
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @param random a source of randomness
     */
    protected Groth21Stage(@NonNull final SignatureSchema signatureSchema, @NonNull final Random random) {
        this.signatureSchema = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
        this.random = Objects.requireNonNull(random, "random must not be null");
    }

    /**
     * Generates a TssMessage from a participantDirectory and a generatingShare
     *
     * @param participantDirectory the candidate tss directory
     * @param generatingShare the secret to redistribute
     * @return a {@link TssMessage} for this share.
     */
    @NonNull
    public TssMessage generateTssMessage(
            @NonNull final TssParticipantDirectory participantDirectory,
            @NonNull final TssPrivateShare generatingShare) {

        final List<Integer> receivingShareIds = participantDirectory.getShareIds();
        final FieldElement secret = generatingShare.privateKey().element();

        // First, crate a polynomial of degree d = threshold -1 so that threshold number of points can recover this
        // polynomial.
        // The value in the free coefficient is the secret that we want to share.
        final FiniteFieldPolynomial finiteFieldPolynomial =
                ShamirUtils.interpolationPolynomial(random, secret, participantDirectory.getThreshold() - 1);
        // The secrets we will end up sharing are the result of evaluating the polynomial with x= receiving-share-id
        final List<FieldElement> secrets =
                receivingShareIds.stream().map(finiteFieldPolynomial::evaluate).toList();
        // Generating some shared entropy for ElGamal encryption algorithm. The randomness is reused for efficiency.
        final List<FieldElement> elGamalRandomness = ElGamalUtils.generateEntropy(
                random, signatureSchema.getPairingFriendlyCurve().field().elementSize(), signatureSchema);
        // This ciphertextTable contains the secrets encrypted for each receiver using the shared randomness and each
        // receiver tssEncryptionKey.
        final CiphertextTable ciphertextTable =
                ElGamalUtils.ciphertextTable(signatureSchema, elGamalRandomness, participantDirectory, secrets);

        // Zk proof: Create a collapsed representation of the cipherTable that can be used for a zk proof.
        final CombinedCiphertext elGamalCombinedCipherText = ciphertextTable.combine(
                signatureSchema.getPairingFriendlyCurve().field().fromLong(ElGamalUtils.TOTAL_NUMBER_OF_ELEMENTS));
        // Zk proof: Create a Feldman polynomial commitment. This allows to validate that the points belong to the
        // polynomial without revealing the polynomial.
        final EcPolynomial commitment =
                ShamirUtils.feldmanCommitment(signatureSchema.getPublicKeyGroup(), finiteFieldPolynomial);
        // Zk proof: Creating the public statement
        final NizkStatement nizkStatement =
                new NizkStatement(receivingShareIds, participantDirectory, commitment, elGamalCombinedCipherText);
        // Zk proof: Creating the private witness
        final NizkWitness nizkWitness = NizkWitness.create(elGamalRandomness, secrets);
        // Zk proof: Creating the private witness
        final NizkProof proof = NizkProof.prove(signatureSchema, random, nizkStatement, nizkWitness);
        return new Groth21Message(
                TssMessage.MESSAGE_CURRENT_VERSION,
                signatureSchema,
                generatingShare.shareId(),
                ciphertextTable,
                commitment,
                proof);
    }

    /**
     * Allows verification of the message against the zk proof and the previous public shares if sent.
     * @param tssTargetParticipantDirectory the directory
     * @param previousPublicShares the previous public shares. optional parameter.
     * @param tssMessage the message to verify
     * @return if the message is valid.
     */
    public boolean verifyTssMessage(
            @NonNull final TssParticipantDirectory tssTargetParticipantDirectory,
            @Nullable final List<TssPublicShare> previousPublicShares,
            @NonNull final TssMessage tssMessage) {
        final Groth21Message message = Groth21Message.fromTssMessage(tssMessage);

        if (message.version() != TssMessage.MESSAGE_CURRENT_VERSION) {
            return false;
        }
        if (message.signatureSchema().getCurve() != signatureSchema.getCurve()
                || message.signatureSchema().getGroupAssignment() != signatureSchema.getGroupAssignment()) {
            return false;
        }

        if (previousPublicShares != null) {
            final BlsPublicKey pk = previousPublicShares.stream()
                    .filter(ps -> ps.shareId().equals(message.generatingShare()))
                    .findAny()
                    .map(TssPublicShare::publicKey)
                    .orElse(null);
            if (pk == null) {
                return false;
            }
            if (!pk.element()
                    .equals(message.polynomialCommitment().coefficients().getFirst())) {
                return false;
            }
        }

        final CombinedCiphertext combinedCipher = message.cipherTable()
                .combine(signatureSchema
                        .getPairingFriendlyCurve()
                        .field()
                        .fromLong(ElGamalUtils.TOTAL_NUMBER_OF_ELEMENTS));
        // Zk proof: Creating the public statement
        final NizkStatement nizkStatement = new NizkStatement(
                tssTargetParticipantDirectory.getShareIds(),
                tssTargetParticipantDirectory,
                message.polynomialCommitment(),
                combinedCipher);

        return message.proof().verify(signatureSchema, nizkStatement);
    }
}
