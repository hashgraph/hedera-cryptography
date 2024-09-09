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

import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingsException;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

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
        final byte[] bytes = this.publicKey.toBytes();
        final ByteBuffer buffer = ByteBuffer.allocate(bytes.length + 1);
        buffer.put(this.signatureSchema.getIdByte());
        buffer.put(bytes);
        return buffer.array();
    }

    /**
     * Returns a {@link PairingPublicKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link PairingPublicKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    public static PairingPublicKey fromBytes(@NonNull final byte[] bytes) {
        final SignatureSchema schema = SignatureSchema.create(bytes);
        final int keySize = schema.getPublicKeyGroup().elementSize();
        if (bytes.length < keySize + 1) throw new IllegalArgumentException("The key representation is invalid");
        try {
            byte[] buffer = Arrays.copyOfRange(bytes, 1, keySize + 1);
            final GroupElement sk = schema.getPublicKeyGroup().fromBytes(buffer);
            return new PairingPublicKey(sk, schema);
        } catch (PairingsException ex) {
            throw new IllegalArgumentException("The key representation is invalid");
        }
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof final PairingPublicKey that)) {
            return false;
        }
        return Objects.equals(publicKey, that.publicKey) && Objects.equals(signatureSchema, that.signatureSchema);
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicKey, signatureSchema);
    }
}
