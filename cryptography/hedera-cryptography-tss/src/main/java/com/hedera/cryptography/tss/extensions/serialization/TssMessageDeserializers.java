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

package com.hedera.cryptography.tss.extensions.serialization;

import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.extensions.EcPolynomial;
import com.hedera.cryptography.pairings.extensions.serialization.FieldElementDeserializers;
import com.hedera.cryptography.pairings.extensions.serialization.GroupElementDeserializers;
import com.hedera.cryptography.pairings.extensions.serialization.GroupElementDeserializers.GroupElementDeserializer;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.impl.elgamal.CipherText;
import com.hedera.cryptography.tss.impl.elgamal.CiphertextTable;
import com.hedera.cryptography.tss.impl.groth21.Groth21Message;
import com.hedera.cryptography.tss.impl.nizk.NizkProof;
import com.hedera.cryptography.utils.serialization.Deserializer;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class TssMessageDeserializers {
    /**
     * Gets a default deserializer for {@link TssMessage}.
     *
     * @param signatureSchema         defines which elliptic curve is used in the protocol, and how it's used
     * @param tssParticipantDirectory the candidate tss directory
     * @return a deserializer
     */
    @SuppressWarnings("unchecked")
    public static <T extends TssMessage> Deserializer<T> defaultDeserializer(
            final SignatureSchema signatureSchema, final TssParticipantDirectory tssParticipantDirectory) {
        return (Deserializer<T>) new DefaultDeserializer(
                signatureSchema, tssParticipantDirectory, GroupElementDeserializers::defaultDeserializer);
    }

    /**
     * Gets a default compressed deserializer for {@link TssMessage}.
     *
     * @param signatureSchema         defines which elliptic curve is used in the protocol, and how it's used
     * @param tssParticipantDirectory the candidate tss directory
     * @return a deserializer
     */
    @SuppressWarnings("unchecked")
    public static <T extends TssMessage> Deserializer<T> compressedDeserializer(
            final SignatureSchema signatureSchema, final TssParticipantDirectory tssParticipantDirectory) {
        return (Deserializer<T>) new DefaultDeserializer(
                signatureSchema, tssParticipantDirectory, GroupElementDeserializers::compressedDeserializer);
    }

    @Deprecated
    public static class Internals {
        public static Deserializer<TssMessage> internalDeserializer(
                final SignatureSchema signatureSchema, final TssParticipantDirectory tssParticipantDirectory) {
            return new DefaultDeserializer(
                    signatureSchema,
                    tssParticipantDirectory,
                    GroupElementDeserializers.Internals::internalDeserializer);
        }
    }
    /**
     * Default deserializer
     */
    static class DefaultDeserializer implements Deserializer<TssMessage> {
        private final SignatureSchema signatureSchema;
        private final Deserializer<FieldElement> fieldElementSerialization;
        private final GroupElementDeserializer groupElementSerialization;
        private final int fieldElementSize;
        private final int groupElementSize;
        private final int totalShares;
        private final int threshold;

        public DefaultDeserializer(
                final SignatureSchema signatureSchema,
                final TssParticipantDirectory tssParticipantDirectory,
                final Function<Group, GroupElementDeserializer> groupDeserializer) {
            this.signatureSchema = signatureSchema;
            this.fieldElementSerialization = FieldElementDeserializers.defautlDeserializer(
                    signatureSchema.getPairingFriendlyCurve().field());
            this.fieldElementSize =
                    signatureSchema.getPairingFriendlyCurve().field().elementSize();
            this.groupElementSerialization = groupDeserializer.apply(signatureSchema.getPublicKeyGroup());
            this.groupElementSize = groupElementSerialization.size();
            this.totalShares = tssParticipantDirectory.getTotalShares();
            this.threshold = tssParticipantDirectory.getThreshold();
        }

        @Override
        public TssMessage deserialize(final byte[] message) {

            final int expectedSize = Integer.BYTES
                    + Integer.BYTES
                    + Integer.BYTES
                    + fieldElementSize * groupElementSize
                    + totalShares * fieldElementSize * groupElementSize
                    + threshold * groupElementSize
                    + groupElementSize * 3
                    + fieldElementSize * 2;

            if (message.length != expectedSize) {
                throw new IllegalStateException("Invalid message length");
            }

            final ByteArrayInputStream buffer = new ByteArrayInputStream(message);
            var is = new DataInputStream(buffer);

            try {

                var version = is.readInt();
                if (version != TssMessage.MESSAGE_CURRENT_VERSION) {
                    throw new IllegalStateException("Invalid message version: " + version);
                }
                var receivedSchema = is.readInt();
                if (receivedSchema > Byte.MAX_VALUE) {
                    throw new IllegalStateException("Invalid message schema: " + receivedSchema);
                }
                if (signatureSchema.toByte() != receivedSchema) {
                    throw new IllegalStateException("Invalid signature schema: " + signatureSchema);
                }
                final int generatingShareElement = is.readInt();
                byte[] buff = new byte[groupElementSize];
                final List<GroupElement> sharedRandomness = new ArrayList<>();
                for (int i = 0; i < fieldElementSize; i++) {
                    is.readNBytes(buff, 0, groupElementSize);
                    groupElementSerialization.consume(sharedRandomness::add, buff);
                }

                final CipherText[] cipherTable = new CipherText[totalShares];
                for (int i = 0; i < totalShares; i++) {
                    final List<GroupElement> values = new ArrayList<>();
                    for (int j = 0; j < fieldElementSize; j++) {
                        is.readNBytes(buff, 0, groupElementSize);
                        groupElementSerialization.consume(values::add, buff);
                    }
                    cipherTable[i] = new CipherText(values);
                }

                final List<GroupElement> polynomialCommitment = new ArrayList<>();
                for (int i = 0; i < threshold; i++) {
                    is.readNBytes(buff, 0, groupElementSize);
                    groupElementSerialization.consume(polynomialCommitment::add, buff);
                }

                is.readNBytes(buff, 0, groupElementSize);
                final GroupElement f = groupElementSerialization.deserialize(buff);
                is.readNBytes(buff, 0, groupElementSize);
                final GroupElement a = groupElementSerialization.deserialize(buff);
                is.readNBytes(buff, 0, groupElementSize);
                final GroupElement y = groupElementSerialization.deserialize(buff);
                buff = new byte[fieldElementSize];
                is.readNBytes(buff, 0, fieldElementSize);
                final FieldElement zR = fieldElementSerialization.deserialize(buff);
                is.readNBytes(buff, 0, fieldElementSize);
                final FieldElement zA = fieldElementSerialization.deserialize(buff);

                final CiphertextTable combinedCipherText = new CiphertextTable(sharedRandomness, cipherTable);
                final NizkProof nizkProof = new NizkProof(f, a, y, zR, zA);
                return new Groth21Message(
                        version,
                        signatureSchema,
                        generatingShareElement,
                        combinedCipherText,
                        new EcPolynomial(polynomialCommitment),
                        nizkProof);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
