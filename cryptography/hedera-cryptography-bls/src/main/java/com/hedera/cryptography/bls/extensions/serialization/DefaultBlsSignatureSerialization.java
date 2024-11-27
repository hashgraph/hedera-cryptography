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
import com.hedera.cryptography.bls.BlsSignature;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.extensions.serialization.DefaultGroupElementSerialization;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;

/**
 * Use this class to construct a deserializer to get a {@link BlsSignature} from an array, or to get a serializer to build the byte[] representation from an instance.
 */
public final class DefaultBlsSignatureSerialization {

    /**
     * Constructor
     */
    private DefaultBlsSignatureSerialization() {
        //static access
    }
    /**
     * Returns a deserializer.
     *
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @return a deserializer
     */
    public static Deserializer<BlsSignature> getDeserializer(SignatureSchema signatureSchema) {
        return new DefaultBlsSignatureSerialization.DefaultDeserializer(signatureSchema);
    }

    /**
     * Returns a serializer.
     *
     * @return the serializer
     */
    public static Serializer<BlsSignature> getSerializer() {
        return new DefaultBlsSignatureSerialization.DefaultSerializer();
    }

    /**
     * Default deserializer
     */
    private static class DefaultDeserializer implements Deserializer<BlsSignature> {
        private final SignatureSchema signatureSchema;
        private final Deserializer<GroupElement> elementDeserializer;
        /**
         * Constructor.
         * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
         */
        public DefaultDeserializer(@NonNull final SignatureSchema signatureSchema) {
            this.signatureSchema = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
            this.elementDeserializer =
                    DefaultGroupElementSerialization.getDeserializer(signatureSchema.getPublicKeyGroup());
        }

        /**
         * Returns a key from a byte array representation.
         * @param element the byte array representing the key
         * @return The instance of the {@link BlsPrivateKey} represented by this element
         */
        @Override
        public BlsSignature deserialize(final @NonNull byte[] element) {
            return new BlsSignature(elementDeserializer.deserialize(element), signatureSchema);
        }
    }

    /**
     * Default serializer
     */
    private static class DefaultSerializer implements Serializer<BlsSignature> {
        private final Serializer<GroupElement> elementSerializer;

        /**
         * Constructor.
         */
        DefaultSerializer() {
            this.elementSerializer = DefaultGroupElementSerialization.getSerializer();
        }

        /**
         * Returns byte array representation from a key instance.
         * @param element the key
         * @return a byte array representation of element
         */
        @Override
        public byte[] serialize(final BlsSignature element) {
            return elementSerializer.serialize(element.element());
        }
    }
}
