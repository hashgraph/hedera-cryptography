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

import static com.hedera.cryptography.bls.ByteArrayConversionUtils.deserializePairingPublicKey;
import static com.hedera.cryptography.bls.ByteArrayConversionUtils.serializePairingPublicKey;

import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 *  An elliptic curve public Key for a {@code PairingFriendlyCurve} under a specific {@link SignatureSchema}
 */
public record BlsPublicKey(GroupElement publicKey, SignatureSchema signatureSchema) {

    /**
     * Serializes this {@link BlsPublicKey} into a byte array.
     *
     * @return the serialized form of this object
     */
    @NonNull
    public byte[] toBytes() {
        return serializePairingPublicKey(this);
    }

    /**
     * Returns a {@link BlsPublicKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link BlsPublicKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    public static BlsPublicKey fromBytes(@NonNull final byte[] bytes) {
        return deserializePairingPublicKey(bytes);
    }

    /**
     * Verifies a signature out of its byte array representation
     * @param signature the serialized form of a signature
     * @param message unsigned message to validate the signature
     * @return true is the provided signature is a valid signature of the message
     * @throws IllegalArgumentException if the signature representation is invalid
     */
    public boolean verifySignature(@NonNull final byte[] signature, @NonNull final byte[] message) {
        final BlsSignature blsSignature = BlsSignature.fromBytes(signature);
        return blsSignature.verify(this, message);
    }
}
