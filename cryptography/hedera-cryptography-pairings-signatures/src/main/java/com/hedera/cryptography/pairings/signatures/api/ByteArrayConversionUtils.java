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

package com.hedera.cryptography.pairings.signatures.api;

import com.hedera.cryptography.pairings.api.PairingsException;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Utility class for converting values to and from byteArrays
 */
class ByteArrayConversionUtils {

    /**
     * Returns a {@link PairingPrivateKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link PairingPrivateKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    static PairingPrivateKey deserializePairingPrivateKey(@NonNull final byte[] bytes) {
        return new Deserializer<>(
                        (s) -> s.getPairingFriendlyCurve().field().elementSize(),
                        (schema, buffer) ->
                                schema.getPairingFriendlyCurve().field().fromBytes(buffer),
                        PairingPrivateKey::new)
                .deserialize(Objects.requireNonNull(bytes, "bytes must not be null"));
    }

    /**
     * Returns a {@link PairingPublicKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link PairingPublicKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    static PairingPublicKey deserializePairingPublicKey(@NonNull final byte[] bytes) {
        return new Deserializer<>(
                        (s) -> s.getPublicKeyGroup().elementSize(),
                        (schema, buffer) -> schema.getPublicKeyGroup().fromBytes(buffer),
                        PairingPublicKey::new)
                .deserialize(Objects.requireNonNull(bytes, "bytes must not be null"));
    }

    /**
     * Returns a {@link PairingSignature} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link PairingSignature} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    static PairingSignature deserializePairingSignature(@NonNull final byte[] bytes) {
        return new Deserializer<>(
                        (s) -> s.getSignatureGroup().elementSize(),
                        (schema, buffer) -> schema.getSignatureGroup().fromBytes(buffer),
                        PairingSignature::new)
                .deserialize(Objects.requireNonNull(bytes, "bytes must not be null"));
    }

    /**
     * Serializes this {@link PairingPrivateKey} into a byte array.
     *
     * @param value  the value to serialize
     * @return the serialized form of this object
     */
    @NonNull
    static byte[] serializePairingPrivateKey(@NonNull final PairingPrivateKey value) {
        return new Serializer(() -> value.privateKey().toBytes(), value.signatureSchema()).toBytes();
    }

    /**
     * Serializes this {@link PairingPublicKey} into a byte array.
     *
     * @param value  the value to serialize
     * @return the serialized form of this object
     */
    @NonNull
    static byte[] serializePairingPublicKey(@NonNull final PairingPublicKey value) {
        return new Serializer(() -> value.publicKey().toBytes(), value.signatureSchema()).toBytes();
    }

    /**
     * Serializes this {@link PairingSignature} into a byte array.
     *
     * @param value  the value to serialize
     * @return the serialized form of this object
     */
    @NonNull
    static byte[] serializePairingSignature(@NonNull final PairingSignature value) {
        return new Serializer(() -> value.signature().toBytes(), value.signatureSchema()).toBytes();
    }

    private record Serializer(Supplier<byte[]> bytesExtractor, SignatureSchema signatureSchema) {
        @NonNull
        public byte[] toBytes() {
            final byte[] bytes = bytesExtractor.get();
            final ByteBuffer buffer = ByteBuffer.allocate(bytes.length + 1);
            buffer.put(this.signatureSchema.getIdByte());
            buffer.put(bytes);
            return buffer.array();
        }
    }

    private record Deserializer<I, D>(
            Function<SignatureSchema, Integer> sizeExtractor,
            BiFunction<SignatureSchema, byte[], I> intermediate,
            BiFunction<I, SignatureSchema, D> deserializer) {
        /**
         * Returns a {@link D} instance out of this object serialized form
         *
         * @param bytes the serialized form of this object
         * @return a {@link D} instance
         * @throws IllegalArgumentException if the deserialization fails
         */
        @NonNull
        public D deserialize(@NonNull final byte[] bytes) {
            final SignatureSchema schema = SignatureSchema.create(bytes);
            final int keySize = sizeExtractor.apply(schema);
            if (bytes.length < keySize + 1) throw new IllegalArgumentException("The key representation is invalid");
            try {
                byte[] buffer = Arrays.copyOfRange(bytes, 1, keySize + 1);
                final I sk = intermediate.apply(schema, buffer);
                return deserializer.apply(sk, schema);
            } catch (PairingsException ex) {
                throw new IllegalArgumentException("The key representation is invalid");
            }
        }
    }
}
