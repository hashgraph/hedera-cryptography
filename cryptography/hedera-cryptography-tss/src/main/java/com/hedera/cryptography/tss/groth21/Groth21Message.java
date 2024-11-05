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

import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.extensions.EcPolynomial;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.extensions.elgamal.CipherText;
import com.hedera.cryptography.tss.extensions.elgamal.CiphertextTable;
import com.hedera.cryptography.tss.extensions.nizk.NizkProof;
import com.hedera.cryptography.utils.ByteArrayUtils.Deserializer;
import com.hedera.cryptography.utils.ByteArrayUtils.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * A message sent as part of either genesis keying, or rekeying.
 * @param version supported version of the message
 * @param signatureSchema Defines which and how elliptic curve is used in the protocol
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
     * Cast or transform a {@link TssMessage} into a {@link Groth21Message}
     * @param tssMessage the message to cast or transform
     * @return the cast or transformed message
     */
    @NonNull
    static Groth21Message fromTssMessage(final @NonNull TssMessage tssMessage) {
        return Objects.requireNonNull(tssMessage, "tssMessage must not be null") instanceof Groth21Message message
                ? message
                : Groth21Message.fromBytes(tssMessage.bytes());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public byte[] bytes() {
        final Serializer serializer = new Serializer()
                .put(version)
                .put(signatureSchema.getIdByte())
                .put(generatingShare)
                .putListSameSize(cipherTable.sharedRandomness(), GroupElement::toBytes)
                .put(cipherTable.shareCiphertexts().length);
        for (int i = 0; i < cipherTable.shareCiphertexts().length; i++) {
            serializer.putListSameSize(cipherTable.shareCiphertexts()[i].cipherText(), GroupElement::toBytes);
        }
        return serializer
                .putListSameSize(polynomialCommitment.coefficients(), GroupElement::toBytes)
                .put(proof.f()::toBytes)
                .put(proof.a()::toBytes)
                .put(proof.y()::toBytes)
                .put(proof.zR()::toBytes)
                .put(proof.zA()::toBytes)
                .toBytes();
    }

    /**
     * Reads a {@link Groth21Message} from its serialized form following the specs in
     * {@link TssMessage#bytes()}
     * @param message the byte array representation of the message
     * @return a Groth21Message instance
     * @throws IllegalStateException if the message cannot be read
     */
    @NonNull
    public static Groth21Message fromBytes(@NonNull final byte[] message) {
        final Deserializer deserializer = new Deserializer(message);
        final int version = deserializer.readInt();
        final SignatureSchema schema = SignatureSchema.create(deserializer.readByte());
        final int fieldElementSize = schema.getPairingFriendlyCurve().field().elementSize();
        final int groupElementSize = schema.getPublicKeyGroup().elementSize();

        final Function<byte[], FieldElement> fieldElementFunction =
                schema.getPairingFriendlyCurve().field()::fromBytes;
        final Function<byte[], GroupElement> groupElementFunction = schema.getPublicKeyGroup()::fromBytes;

        final int generatingShareElement = deserializer.readInt();
        final List<GroupElement> sharedRandomness =
                deserializer.readListSameSize(groupElementFunction, groupElementSize);
        final int elements = deserializer.readInt();
        final CipherText[] cipherTable = new CipherText[elements];
        for (int i = 0; i < elements; i++) {
            final List<GroupElement> values = deserializer.readListSameSize(groupElementFunction, groupElementSize);
            cipherTable[i] = new CipherText(values);
        }
        final List<GroupElement> polynomialCommitment =
                deserializer.readListSameSize(groupElementFunction, groupElementSize);
        final GroupElement f = deserializer.read(groupElementFunction, groupElementSize);
        final GroupElement a = deserializer.read(groupElementFunction, groupElementSize);
        final GroupElement y = deserializer.read(groupElementFunction, groupElementSize);
        final FieldElement zR = deserializer.read(fieldElementFunction, fieldElementSize);
        final FieldElement zA = deserializer.read(fieldElementFunction, fieldElementSize);

        final CiphertextTable combinedCipherText = new CiphertextTable(sharedRandomness, cipherTable);
        final NizkProof nizkProof = new NizkProof(f, a, y, zR, zA);
        return new Groth21Message(
                version,
                schema,
                generatingShareElement,
                combinedCipherText,
                new EcPolynomial(polynomialCommitment),
                nizkProof);
    }
}
