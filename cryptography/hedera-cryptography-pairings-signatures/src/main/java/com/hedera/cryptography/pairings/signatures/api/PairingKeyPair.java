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

import edu.umd.cs.findbugs.annotations.NonNull;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Represents a pairing key pair.
 *
 * @param privateKey the private key
 * @param publicKey  the public key
 */
public record PairingKeyPair(@NonNull PairingPrivateKey privateKey, @NonNull PairingPublicKey publicKey) {
    /**
     * Constructs a new PairingKeyPair
     *
     * @param privateKey the private key
     * @param publicKey  the public key
     */
    public PairingKeyPair {
        Objects.requireNonNull(privateKey, "privateKey cannot be null");
        Objects.requireNonNull(publicKey, "publicKey cannot be null");
        if (privateKey.signatureSchema() != publicKey.signatureSchema()) {
            throw new IllegalArgumentException("The private key and public key must have the same signature schema");
        }
    }

    /**
     * Generates a Key Pair (private and public keys)
     *
     * @param signatureSchema the signature schema to use
     * @return a key pair
     * @throws NoSuchAlgorithmException if no algorithm found to get a {@link SecureRandom} instance
     */
    @NonNull
    public static PairingKeyPair generate(@NonNull SignatureSchema signatureSchema)
            throws NoSuchAlgorithmException {
        final PairingPrivateKey pairingPrivateKey =
                PairingPrivateKey.create(Objects.requireNonNull(signatureSchema, "signatureSchema cannot be null"),
                        SecureRandom.getInstanceStrong());
        return new PairingKeyPair(pairingPrivateKey, pairingPrivateKey.createPublicKey());
    }
}
