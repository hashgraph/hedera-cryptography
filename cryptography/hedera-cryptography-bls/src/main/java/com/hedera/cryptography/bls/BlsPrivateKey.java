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

import static com.hedera.cryptography.bls.SerializationUtils.deserializePairingPrivateKey;
import static com.hedera.cryptography.bls.SerializationUtils.serializePairingPrivateKey;

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;
import java.util.Random;

/**
 *  A bls private Key for a {@code PairingFriendlyCurve} under a specific {@link SignatureSchema}
 * @param element the element
 * @param signatureSchema the signatureSchema
 */
public record BlsPrivateKey(@NonNull FieldElement element, @NonNull SignatureSchema signatureSchema) {
    /**
     * Constructor.
     *
     * @param element the element
     * @param signatureSchema the signature schema
     */
    public BlsPrivateKey {
        Objects.requireNonNull(element, "element must not be null");
        Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
    }

    /**
     * Creates a private key out of the CurveType and a random
     *
     * @param signatureSchema   The implementing curve type
     * @param random The environment secureRandom to use
     * @return a privateKey for that CurveType
     */
    @NonNull
    public static BlsPrivateKey create(@NonNull final SignatureSchema signatureSchema, @NonNull final Random random) {
        final Field field = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null")
                .getPairingFriendlyCurve()
                .field();
        Objects.requireNonNull(random, "random must not be null");
        final FieldElement zero = field.fromLong(0);
        final FieldElement one = field.fromLong(1);
        FieldElement sk = field.random(random);
        while (sk.equals(zero) || sk.equals(one)) {
            sk = field.random(random);
        }
        return new BlsPrivateKey(sk, signatureSchema);
    }

    /**
     * Create a public key from this private key.
     *
     * @return the public key
     */
    @NonNull
    public BlsPublicKey createPublicKey() {
        final GroupElement pk =
                this.signatureSchema.getPublicKeyGroup().generator().multiply(this.element);

        return new BlsPublicKey(pk, this.signatureSchema);
    }

    /**
     * Signs a message and returns the signature
     *
     * @param message the message to sign
     * @return the signature of the message represented by {@code message}
     */
    @NonNull
    public BlsSignature sign(final @NonNull byte[] message) {
        final GroupElement o =
                signatureSchema.getSignatureGroup().hashToCurve(message).multiply(this.element);
        return new BlsSignature(o, signatureSchema);
    }

    /**
     * Serializes this {@link BlsPrivateKey} into a byte array.
     *
     * @return the serialized form of this object
     */
    @NonNull
    public byte[] toBytes() {
        return serializePairingPrivateKey(this);
    }

    /**
     * Returns a {@link BlsPrivateKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link BlsPrivateKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    public static BlsPrivateKey fromBytes(@NonNull final byte[] bytes) {
        return deserializePairingPrivateKey(bytes);
    }
}
