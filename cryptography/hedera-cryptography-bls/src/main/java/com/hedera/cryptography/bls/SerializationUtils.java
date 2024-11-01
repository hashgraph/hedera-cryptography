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

import com.hedera.cryptography.utils.TransportUtils;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Utility class for converting values to and from byteArrays
 */
class SerializationUtils {

    /**
     * Returns a {@link BlsPrivateKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link BlsPrivateKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    static BlsPrivateKey deserializePairingPrivateKey(@NonNull final byte[] bytes) {
        try {
            final TransportUtils.Deserializer deserializer = new TransportUtils.Deserializer(bytes);
            var schema = SignatureSchema.create(deserializer.readByte());
            var element = deserializer.read(
                    schema.getPairingFriendlyCurve().field()::fromBytes,
                    schema.getPairingFriendlyCurve().field().elementSize());
            return new BlsPrivateKey(element, schema);
        } catch (IllegalStateException e) {
            throw new IllegalArgumentException("Unable to deserialize pairing private key", e);
        }
    }

    /**
     * Returns a {@link BlsPublicKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link BlsPublicKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    static BlsPublicKey deserializePairingPublicKey(@NonNull final byte[] bytes) {
        try {

            final TransportUtils.Deserializer deserializer = new TransportUtils.Deserializer(bytes);
            var schema = SignatureSchema.create(deserializer.readByte());
            var element = deserializer.read(
                    schema.getPublicKeyGroup()::fromBytes,
                    schema.getPublicKeyGroup().elementSize());
            return new BlsPublicKey(element, schema);
        } catch (IllegalStateException e) {
            throw new IllegalArgumentException("Unable to deserialize pairing public key", e);
        }
    }

    /**
     * Returns a {@link BlsSignature} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link BlsSignature} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    static BlsSignature deserializePairingSignature(@NonNull final byte[] bytes) {
        try {
            final TransportUtils.Deserializer deserializer = new TransportUtils.Deserializer(bytes);
            var schema = SignatureSchema.create(deserializer.readByte());
            var element = deserializer.read(
                    schema.getSignatureGroup()::fromBytes,
                    schema.getSignatureGroup().elementSize());
            return new BlsSignature(element, schema);
        } catch (IllegalStateException e) {
            throw new IllegalArgumentException("Unable to deserialize pairing private key", e);
        }
    }

    /**
     * Serializes this {@link BlsPrivateKey} into a byte array.
     *
     * @param value  the value to serialize
     * @return the serialized form of this object
     */
    @NonNull
    static byte[] serializePairingPrivateKey(@NonNull final BlsPrivateKey value) {
        return new TransportUtils.Serializer()
                .put(value.signatureSchema().getIdByte())
                .put(value.element()::toBytes)
                .toBytes();
    }

    /**
     * Serializes this {@link BlsPublicKey} into a byte array.
     *
     * @param value  the value to serialize
     * @return the serialized form of this object
     */
    @NonNull
    static byte[] serializePairingPublicKey(@NonNull final BlsPublicKey value) {
        return new TransportUtils.Serializer()
                .put(value.signatureSchema().getIdByte())
                .put(value.element()::toBytes)
                .toBytes();
    }

    /**
     * Serializes this {@link BlsSignature} into a byte array.
     *
     * @param value  the value to serialize
     * @return the serialized form of this object
     */
    @NonNull
    static byte[] serializePairingSignature(@NonNull final BlsSignature value) {
        return new TransportUtils.Serializer()
                .put(value.signatureSchema().getIdByte())
                .put(value.element()::toBytes)
                .toBytes();
    }
}
