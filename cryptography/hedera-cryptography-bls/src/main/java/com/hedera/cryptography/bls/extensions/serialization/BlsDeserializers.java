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
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.extensions.serialization.FieldElementDeserializers;
import com.hedera.cryptography.pairings.extensions.serialization.GroupElementDeserializers;
import com.hedera.cryptography.utils.serialization.Deserializer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;

/**
 * All Bls deserializers
 * Use returned objects of this class to construct objects from a byte[] array.
 */
public class BlsDeserializers {

    /**
     * Gets a deserializer for {@link BlsPrivateKey}
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @return a deserializer
     */
    public static Deserializer<BlsPrivateKey> privateKeyDeserializer(@NonNull final SignatureSchema signatureSchema) {
        Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
        final var fd = FieldElementDeserializers.defautlDeserializer(
                signatureSchema.getSignatureGroup().field());
        return element -> new BlsPrivateKey(fd.deserialize(element), signatureSchema);
    }

    /**
     * Gets a deserializer for {@link BlsPublicKey}.
     *
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @return a deserializer
     */
    public static Deserializer<BlsPublicKey> publicKeyDeserializer(@NonNull final SignatureSchema signatureSchema) {
        Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
        final var gd = GroupElementDeserializers.defaultDeserializer(signatureSchema.getPublicKeyGroup());
        return element -> new BlsPublicKey(gd.deserialize(element), signatureSchema);
    }

    /**
     * Gets a deserializer.
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @return a deserializer
     */
    public static Deserializer<BlsSignature> signatureDeserializer(@NonNull final SignatureSchema signatureSchema) {
        Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
        final var gd = GroupElementDeserializers.defaultDeserializer(signatureSchema.getSignatureGroup());
        return element -> new BlsSignature(gd.deserialize(element), signatureSchema);
    }
}
