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

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingsException;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;

/**
 *  An elliptic curve private Key for a {@code PairingFriendlyCurve} under a specific {@link SignatureSchema}
 */
public class PairingPrivateKey {

    private final FieldElement privateKey;
    private final SignatureSchema signatureSchema;

    private PairingPrivateKey(final FieldElement privateKey, final SignatureSchema signatureSchema) {
        this.privateKey = privateKey;
        this.signatureSchema = signatureSchema;
    }

    /**
     * Creates a private key out of the CurveType and a random
     *
     * @param signatureSchema   The implementing curve type
     * @param random The environment secureRandom to use
     * @return a privateKey for that CurveType
     */
    @NonNull
    public static PairingPrivateKey create(
            @NonNull final SignatureSchema signatureSchema, @NonNull final Random random) {
        final FieldElement sk = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null")
                .getPairingFriendlyCurve()
                .field()
                .random(Objects.requireNonNull(random, "random must not be null"));
        return new PairingPrivateKey(sk, signatureSchema);
    }

    /**
     * Create a public key from this private key.
     *
     * @return the public key
     */
    public PairingPublicKey createPublicKey() {
        final GroupElement pk =
                this.signatureSchema.getPublicKeyGroup().generator().multiply(this.privateKey);

        return new PairingPublicKey(pk, this.signatureSchema);
    }

    /**
     * Signs a message and returns the signature
     *
     * @return the signature of the message represented by {@code message}
     */
    @NonNull
    public PairingSignature sign(final @NonNull byte[] message) {
        Objects.requireNonNull(message, "message must not be null");
        return new PairingSignature();
    }

    /**
     * Serializes this {@link PairingPrivateKey} into a byte array.
     *
     * @return the serialized form of this object
     */
    @NonNull
    public byte[] toBytes() {
        final byte[] bytes = this.privateKey.toBytes();
        final ByteBuffer buffer = ByteBuffer.allocate(bytes.length + 1);
        buffer.put(this.signatureSchema.getIdByte());
        buffer.put(bytes);
        return buffer.array();
    }

    /**
     * Returns a {@link PairingPrivateKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link PairingPrivateKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    public static PairingPrivateKey fromBytes(@NonNull final byte[] bytes) {
        final SignatureSchema schema = ValidationUtils.getAndValidateSignatureSchema(bytes);
        final int keySize = schema.getPairingFriendlyCurve().field().elementSize();
        if(bytes.length < keySize +1)
            throw new IllegalArgumentException("The key representation is invalid");
        byte[] buffer = Arrays.copyOfRange(bytes, 1, keySize+1);
        try {
            final FieldElement sk = schema.getPairingFriendlyCurve()
                    .field()
                    .fromBytes(buffer);
            return new PairingPrivateKey(sk, schema);
        } catch (PairingsException ex) {
            throw new IllegalArgumentException("The key representation is invalid");
        }
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof final PairingPrivateKey that)) {
            return false;
        }
        return Objects.equals(privateKey, that.privateKey) && Objects.equals(signatureSchema,
                that.signatureSchema);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateKey, signatureSchema);
    }
}
