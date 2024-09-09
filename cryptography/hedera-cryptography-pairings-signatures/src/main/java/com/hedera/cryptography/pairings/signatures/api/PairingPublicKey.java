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

import static com.hedera.cryptography.pairings.signatures.api.ByteArrayConversionUtils.deserializePairingPublicKey;
import static com.hedera.cryptography.pairings.signatures.api.ByteArrayConversionUtils.serializePairingPublicKey;

import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 *  An elliptic curve public Key for a {@code PairingFriendlyCurve} under a specific {@link SignatureSchema}
 */
public record PairingPublicKey(GroupElement publicKey, SignatureSchema signatureSchema) {

    /**
     * Serializes this {@link PairingPublicKey} into a byte array.
     *
     * @return the serialized form of this object
     */
    @NonNull
    public byte[] toBytes() {
        return serializePairingPublicKey(this);
    }

    /**
     * Returns a {@link PairingPublicKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link PairingPublicKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    public static PairingPublicKey fromBytes(@NonNull final byte[] bytes) {
        return deserializePairingPublicKey(bytes);
    }
}
