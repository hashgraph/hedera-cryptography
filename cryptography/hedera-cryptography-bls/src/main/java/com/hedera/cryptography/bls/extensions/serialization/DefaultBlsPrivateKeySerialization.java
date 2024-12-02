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

package com.hedera.cryptography.bls.extensions.serialization;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.extensions.serialization.DefaultFieldElementSerialization;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;

/**
 * Use this class to construct a {@link BlsPrivateKey} from an array, or to get the byte[] representation from an instance.
 */
public final class DefaultBlsPrivateKeySerialization {

    /**
     * Constructor
     */
    private DefaultBlsPrivateKeySerialization() {
        // static access
    }

    /**
     * Gets a deserializer.
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @return a deserializer
     */
    public static Deserializer<BlsPrivateKey> getDeserializer(@NonNull final SignatureSchema signatureSchema) {
        Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
        return new DefaultDeserializer(
                signatureSchema,
                DefaultFieldElementSerialization.getDeserializer(
                        signatureSchema.getPairingFriendlyCurve().field()));
    }

    /**
     * Gets a serializer.
     * @return a serializer
     */
    public static Serializer<BlsPrivateKey> getSerializer() {
        return new DefaultSerializer(DefaultFieldElementSerialization.getSerializer());
    }

    /**
     * Deserializer
     */
    private record DefaultDeserializer(SignatureSchema signatureSchema, Deserializer<FieldElement> elementDeserializer)
            implements Deserializer<BlsPrivateKey> {

        /**
         * Returns a key from a byte array representation.
         * @param element the byte array representing the key
         * @return The instance of the {@link BlsPrivateKey} represented by this element
         */
        @Override
        public BlsPrivateKey deserialize(final @NonNull byte[] element) {
            return new BlsPrivateKey(elementDeserializer.deserialize(element), signatureSchema);
        }
    }

    /**
     * Serializer
     */
    private record DefaultSerializer(Serializer<FieldElement> elementSerializer) implements Serializer<BlsPrivateKey> {
        /**
         * Returns byte array representation from a key instance.
         * @param element the key
         * @return a byte array representation of element
         * @throws IllegalStateException if the key cannot be read
         */
        @Override
        public byte[] serialize(final BlsPrivateKey element) {
            try {
                return elementSerializer.serialize(element.element());
            } catch (Exception e) {
                throw new IllegalStateException("Unable to serialize BlsPrivateKey", e);
            }
        }
    }
}
