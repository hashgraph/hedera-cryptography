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
import com.hedera.cryptography.pairings.extensions.serialization.DefaultFieldElementSerialization;
import com.hedera.cryptography.pairings.extensions.serialization.DefaultGroupElementSerialization;
import com.hedera.cryptography.pairings.extensions.serialization.DefaultGroupElementSerialization.GroupElementDeserializer;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.impl.elgamal.CipherText;
import com.hedera.cryptography.tss.impl.elgamal.CiphertextTable;
import com.hedera.cryptography.tss.impl.groth21.Groth21Message;
import com.hedera.cryptography.tss.impl.nizk.NizkProof;
import com.hedera.cryptography.utils.ByteArrayUtils;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * Use this class to construct a deserializer to get a {@link TssMessage} from an array, or to get a serializer to build the byte[] representation from an instance.
 * <br>
 * Specification of the format:
 * <p>
 * Given:
 *  <ul>
 *      <li>{@code e}: {@link FieldElement#size()}</li>
 *      <li>{@code g}: {@link GroupElement#size()} of {@link SignatureSchema#getPublicKeyGroup()}</li>
 *      <li>{@code t}: threshold value</li>
 *      <li>{@code s}: total-shares (Participants*Shares)</li>
 *  </ul>
 *<p>
 * A {@link TssMessage} byte representation produced with this class will consist of:
 * <ul>
 *     <li>4 bytes (big-endian) representing the version of the message. Must be {@code MESSAGE_CURRENT_VERSION} constant value</li>
 *     <li>4 bytes for {@link SignatureSchema} that originated the message.</li>
 *     <li>4 bytes (big-endian) representing the shareId that originated the message.</li>
 *     <li>A list of {@code e} elements, each of size {@code g} bytes, representing the shared randomness (total of {@code e * g} bytes).</li>
 *     <li>{@code s} lists of {@code e} elements, each of size {@code g} bytes, representing the encrypted shares (total of {@code s * e * g} bytes).</li>
 *     <li>A list of {@code t} elements, each of size {@code g} bytes, representing the polynomial commitment (total of {@code t * g} bytes).</li>
 *     <li>{@code g} bytes representing the proof element {@code f}.</li>
 *     <li>{@code g} bytes representing the proof element {@code a}.</li>
 *     <li>{@code g} bytes representing the proof element {@code y}.</li>
 *     <li>{@code e} bytes representing the proof scalar {@code zr}.</li>
 *     <li>{@code e} bytes representing the proof scalar {@code za}.</li>
 * </ul>
 */
public class DefaultTssMessageSerialization {
    /**
     * Constructor
     */
    private DefaultTssMessageSerialization() {
        // Nothing
    }

    /**
     * Gets a deserializer.
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @param tssParticipantDirectory the candidate tss directory
     * @return a deserializer
     */
    public static Deserializer<TssMessage> getDeserializer(
            final SignatureSchema signatureSchema, final TssParticipantDirectory tssParticipantDirectory) {
        return new DefaultDeserializer(
                signatureSchema, tssParticipantDirectory, DefaultGroupElementSerialization::getDeserializer);
    }

    public static Deserializer<TssMessage> getNonValidatedDeserializer(
            final SignatureSchema signatureSchema, final TssParticipantDirectory tssParticipantDirectory) {
        return new DefaultDeserializer(
                signatureSchema,
                tssParticipantDirectory,
                DefaultGroupElementSerialization::getNonValidatedDeserializer);
    }

    public static Deserializer<TssMessage> getCompressedDeserializer(
            final SignatureSchema signatureSchema, final TssParticipantDirectory tssParticipantDirectory) {
        return new DefaultDeserializer(
                signatureSchema,
                tssParticipantDirectory,
                DefaultGroupElementSerialization::getCompressedValidatedDeserializer);
    }

    /**
     * Gets a serializer.
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @return a serializer
     */
    public static Serializer<TssMessage> getSerializer(final SignatureSchema signatureSchema) {
        return new DefaultSerializer(
                signatureSchema,
                DefaultFieldElementSerialization.getSerializer(),
                DefaultGroupElementSerialization.getSerializer());
    }

    public static Serializer<TssMessage> getCompressedSerializer(final SignatureSchema signatureSchema) {
        return new DefaultSerializer(
                signatureSchema,
                DefaultFieldElementSerialization.getSerializer(),
                DefaultGroupElementSerialization.getComrpessSerializer());
    }
    /**
     * Default deserializer
     */
    private static class DefaultDeserializer implements Deserializer<TssMessage> {
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
            this.fieldElementSerialization = DefaultFieldElementSerialization.getDeserializer(
                    signatureSchema.getPairingFriendlyCurve().field());
            this.fieldElementSize =
                    signatureSchema.getPairingFriendlyCurve().field().elementSize();
            this.groupElementSerialization = groupDeserializer.apply(signatureSchema.getPublicKeyGroup());
            this.groupElementSize = groupElementSerialization.elementSize();
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

    /**
     * Default Serializer
     */
    private record DefaultSerializer(
            SignatureSchema signatureSchema,
            Serializer<FieldElement> fieldElementSerialization,
            Serializer<GroupElement> groupElementSerialization)
            implements Serializer<TssMessage> {

        @NonNull
        @Override
        public byte[] serialize(@NonNull final TssMessage element) {
            final ByteArrayOutputStream output = new ByteArrayOutputStream();
            try {
                output.write(ByteArrayUtils.toByteArray(TssMessage.MESSAGE_CURRENT_VERSION));
                output.write(ByteArrayUtils.toByteArray(signatureSchema.toByte()));
                output.write(ByteArrayUtils.toByteArray(element.generatingShare()));

                for (GroupElement randomness : element.sharedRandomness()) {
                    output.write(groupElementSerialization.serialize(randomness));
                }
                for (List<GroupElement> cipher : element.shareCiphertexts()) {
                    for (GroupElement c : cipher) {
                        output.write(groupElementSerialization.serialize(c));
                    }
                }
                for (GroupElement comm : element.polynomialCommitments()) {
                    output.write(groupElementSerialization.serialize(comm));
                }
                output.write(groupElementSerialization.serialize(element.f()));
                output.write(groupElementSerialization.serialize(element.a()));
                output.write(groupElementSerialization.serialize(element.y()));
                output.write(fieldElementSerialization.serialize(element.zR()));
                output.write(fieldElementSerialization.serialize(element.zA()));
                return output.toByteArray();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
