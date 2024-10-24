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

package com.hedera.cryptography.bls;

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
     * Returns a {@link BlsPrivateKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link BlsPrivateKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    static BlsPrivateKey deserializePairingPrivateKey(@NonNull final byte[] bytes) {
        return new Deserializer<>(
                        (s) -> s.getPairingFriendlyCurve().field().elementSize(),
                        (schema, buffer) ->
                                schema.getPairingFriendlyCurve().field().fromBytes(buffer),
                        BlsPrivateKey::new)
                .deserialize(Objects.requireNonNull(bytes, "bytes must not be null"));
    }

    /**
     * Returns a {@link BlsPublicKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link BlsPublicKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    static BlsPublicKey deserializePairingPublicKey(@NonNull final byte[] bytes) {
        return new Deserializer<>(
                        (s) -> s.getPublicKeyGroup().elementSize(),
                        (schema, buffer) -> schema.getPublicKeyGroup().fromBytes(buffer),
                        BlsPublicKey::new)
                .deserialize(Objects.requireNonNull(bytes, "bytes must not be null"));
    }

    /**
     * Returns a {@link BlsSignature} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link BlsSignature} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    static BlsSignature deserializePairingSignature(@NonNull final byte[] bytes) {
        return new Deserializer<>(
                        (s) -> s.getSignatureGroup().elementSize(),
                        (schema, buffer) -> schema.getSignatureGroup().fromBytes(buffer),
                        BlsSignature::new)
                .deserialize(Objects.requireNonNull(bytes, "bytes must not be null"));
    }

    /**
     * Serializes this {@link BlsPrivateKey} into a byte array.
     *
     * @param value  the value to serialize
     * @return the serialized form of this object
     */
    @NonNull
    static byte[] serializePairingPrivateKey(@NonNull final BlsPrivateKey value) {
        return new Serializer(() -> value.element().toBytes(), value.signatureSchema()).toBytes();
    }

    /**
     * Serializes this {@link BlsPublicKey} into a byte array.
     *
     * @param value  the value to serialize
     * @return the serialized form of this object
     */
    @NonNull
    static byte[] serializePairingPublicKey(@NonNull final BlsPublicKey value) {
        return new Serializer(() -> value.element().toBytes(), value.signatureSchema()).toBytes();
    }

    /**
     * Serializes this {@link BlsSignature} into a byte array.
     *
     * @param value  the value to serialize
     * @return the serialized form of this object
     */
    @NonNull
    static byte[] serializePairingSignature(@NonNull final BlsSignature value) {
        return new Serializer(() -> value.element().toBytes(), value.signatureSchema()).toBytes();
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
