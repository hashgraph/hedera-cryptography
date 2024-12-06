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
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.BlsSignature;
import com.hedera.cryptography.pairings.extensions.serialization.FieldElementSerializers;
import com.hedera.cryptography.pairings.extensions.serialization.GroupElementSerializers;
import com.hedera.cryptography.utils.serialization.Serializer;
import com.hedera.cryptography.utils.serialization.Transformer;

/**
 * Use this class to construct a {@link BlsPrivateKey} from an array, or to get the byte[] representation from an instance.
 */
public final class BlsSerializers {

    /**
     * Constructor
     */
    private BlsSerializers() {
        // static access
    }

    /**
     * Gets a serializer for {@link BlsPrivateKey}.
     * @return a serializer
     */
    public static Serializer<BlsPrivateKey> privateKeySerializer() {
        return new ErrorCatcherSerializer<>(
                key -> FieldElementSerializers.defaultSerializer().serialize(key.element()));
    }

    /**
     * Gets a serializer for {@link BlsPublicKey}.
     * @return a serializer
     */
    public static Serializer<BlsPublicKey> publicKeySerializer() {
        return new ErrorCatcherSerializer<>(
                key -> GroupElementSerializers.defaultSerializer().serialize(key.element()));
    }

    /**
     * Gets a serializer for {@link BlsSignature}
     * @return a serializer
     */
    public static Serializer<BlsSignature> signatureSerializer() {
        return new ErrorCatcherSerializer<>(
                signature -> GroupElementSerializers.defaultSerializer().serialize(signature.element()));
    }

    /**
     * Serializer
     */
    private record ErrorCatcherSerializer<T>(Transformer<T, byte[]> elementSerializer) implements Serializer<T> {
        /**
         * Returns byte array representation from a key instance.
         * @param element the key
         * @return a byte array representation of element
         * @throws IllegalStateException if the key cannot be read
         */
        @Override
        public byte[] serialize(final T element) {
            try {
                return elementSerializer.transform(element);
            } catch (Exception e) {
                throw new IllegalStateException("Unable to serialize BlsPrivateKey", e);
            }
        }
    }
}
