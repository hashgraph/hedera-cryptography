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

package com.hedera.cryptography.tss.impl.groth21;

import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.extensions.EcPolynomial;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.extensions.serialization.DefaultTssMessageSerialization;
import com.hedera.cryptography.tss.impl.elgamal.CipherText;
import com.hedera.cryptography.tss.impl.elgamal.CiphertextTable;
import com.hedera.cryptography.tss.impl.nizk.NizkProof;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Arrays;
import java.util.List;

/**
 * A message sent as part of either genesis keying, or rekeying.
 * @param version supported version of the message
 * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
 * @param generatingShare share generating the message
 * @param cipherTable an ElGamal cipher per receiving share
 * @param polynomialCommitment a FeldmanCommitment
 * @param proof a Nizk proof
 */
public record Groth21Message(
        int version,
        @NonNull SignatureSchema signatureSchema,
        @NonNull Integer generatingShare,
        @NonNull CiphertextTable cipherTable,
        @NonNull EcPolynomial polynomialCommitment,
        @NonNull NizkProof proof)
        implements TssMessage {

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public byte[] toBytes() {
        return DefaultTssMessageSerialization.getSerializer(signatureSchema).serialize(this);
    }

    @NonNull
    @Override
    public Integer generatingShare() {
        return generatingShare;
    }

    @NonNull
    @Override
    public List<GroupElement> sharedRandomness() {
        return cipherTable.sharedRandomness();
    }

    @NonNull
    @Override
    public List<List<GroupElement>> shareCiphertexts() {
        return Arrays.stream(cipherTable.shareCiphertexts())
                .map(CipherText::cipherText)
                .toList();
    }

    @NonNull
    @Override
    public List<GroupElement> polynomialCommitments() {
        return polynomialCommitment.coefficients();
    }

    @NonNull
    @Override
    public GroupElement f() {
        return proof.f();
    }

    @NonNull
    @Override
    public GroupElement a() {
        return proof.a();
    }

    @NonNull
    @Override
    public GroupElement y() {
        return proof.y();
    }

    @NonNull
    @Override
    public FieldElement zR() {
        return proof.zR();
    }

    @NonNull
    @Override
    public FieldElement zA() {
        return proof.zA();
    }

    /**
     * Reads a {@link Groth21Message} from its serialized form following the specs in {@link TssMessage#toBytes()}
     *
     * @param message the byte array representation of the message
     * @param tssParticipantDirectory the candidate tss directory
     * @param expectedSchema the signatureSchema expected
     * @return a Groth21Message instance
     * @throws IllegalStateException if the message cannot be read
     */
    @NonNull
    public static Groth21Message fromBytes(
            @NonNull final byte[] message,
            @NonNull final TssParticipantDirectory tssParticipantDirectory,
            @NonNull final SignatureSchema expectedSchema) {
        return (Groth21Message) DefaultTssMessageSerialization.getDeserializer(expectedSchema, tssParticipantDirectory)
                .deserialize(message);
    }
}
