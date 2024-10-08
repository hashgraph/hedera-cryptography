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

import static com.hedera.cryptography.pairings.signatures.api.ByteArrayConversionUtils.deserializePairingPrivateKey;
import static com.hedera.cryptography.pairings.signatures.api.ByteArrayConversionUtils.serializePairingPrivateKey;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;
import java.util.Random;

/**
 *  An elliptic curve private Key for a {@code PairingFriendlyCurve} under a specific {@link SignatureSchema}
 */
public record PairingPrivateKey(@NonNull FieldElement privateKey, @NonNull SignatureSchema signatureSchema) {

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
     * @param message the message to sign
     * @return the signature of the message represented by {@code message}
     */
    @NonNull
    public PairingSignature sign(final @NonNull byte[] message) {
        final GroupElement o =
                signatureSchema.getSignatureGroup().fromHash(message).multiply(this.privateKey);
        return new PairingSignature(o, signatureSchema);
    }

    /**
     * Serializes this {@link PairingPrivateKey} into a byte array.
     *
     * @return the serialized form of this object
     */
    @NonNull
    public byte[] toBytes() {
        return serializePairingPrivateKey(this);
    }

    /**
     * Returns a {@link PairingPrivateKey} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link PairingPrivateKey} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    public static PairingPrivateKey fromBytes(@NonNull final byte[] bytes) {
        return deserializePairingPrivateKey(bytes);
    }
}
