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
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.extensions.serialization.FieldElementSerializers;
import com.hedera.cryptography.pairings.extensions.serialization.GroupElementDeserializers;
import com.hedera.cryptography.pairings.extensions.serialization.GroupElementSerializers;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.extensions.serialization.TssMessageDeserializers.DefaultDeserializer;
import com.hedera.cryptography.utils.ByteArrayUtils;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Use this class to get a serializer to build the byte[] representation from an instance.
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
 *     <li>4 bytes for {@link com.hedera.cryptography.bls.GroupAssignment} that originated the message.</li>
 *     <li>4 bytes for {@link com.hedera.cryptography.pairings.api.Curve} that originated the message.</li>
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
public class TssMessageSerializers {
    /**
     * Constructor
     */
    private TssMessageSerializers() {
        // Nothing
    }

    /**
     * Gets a serializer.
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @return a serializer
     */
    public static Serializer<TssMessage> defaultSerializer(final SignatureSchema signatureSchema) {
        return new DefaultSerializer(
                signatureSchema,
                FieldElementSerializers.defaultSerializer(),
                GroupElementSerializers.defaultSerializer());
    }

    public static Serializer<TssMessage> compressedSerializer(final SignatureSchema signatureSchema) {
        return new DefaultSerializer(
                signatureSchema,
                FieldElementSerializers.defaultSerializer(),
                GroupElementSerializers.comrpessSerializer());
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

        public static Deserializer<TssMessage> internalNonValidatedDeserializer(
                final SignatureSchema signatureSchema, final TssParticipantDirectory tssParticipantDirectory) {
            return new DefaultDeserializer(
                    signatureSchema,
                    tssParticipantDirectory,
                    GroupElementDeserializers.Internals::internalNonValidatedDeserializer);
        }

        public static Deserializer<TssMessage> internalCompressedDeserializer(
                final SignatureSchema signatureSchema, final TssParticipantDirectory tssParticipantDirectory) {
            return new DefaultDeserializer(
                    signatureSchema,
                    tssParticipantDirectory,
                    GroupElementDeserializers.Internals::internalCompressedDeserializer);
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
