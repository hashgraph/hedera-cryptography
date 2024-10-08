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

package com.hedera.cryptography.eckeygen;

import com.hedera.cryptography.pairings.signatures.api.PairingKeyPair;
import com.hedera.cryptography.pairings.signatures.api.PairingPrivateKey;
import com.hedera.cryptography.pairings.signatures.api.SignatureSchema;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Service class for creating Bls Keys in base64 encoding
 */
public class KeysGenerationService {
    private final SignatureSchema signatureSchema;

    /**
     * Creates a new instance of this service.
     *
     * @param signatureSchema  Elliptic Curve predefined configuration for this utility
     */
    public KeysGenerationService(@NonNull final SignatureSchema signatureSchema) {
        this.signatureSchema = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
    }

    /**
     * Generates a Key Pair (private and public keys)
     *
     * @return a key pair
     */
    public PairingKeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final PairingPrivateKey pairingPrivateKey =
                PairingPrivateKey.create(signatureSchema, SecureRandom.getInstanceStrong());
        return new PairingKeyPair(pairingPrivateKey, pairingPrivateKey.createPublicKey());
    }

    /**
     * An exception thrown in case of generation error
     */
    public static class KeysServiceException extends RuntimeException {
        /**
         * Retrieves a specific RuntimeException
         * @param message details of the error
         */
        public KeysServiceException(@NonNull final String message) {
            super(message);
        }
    }
}
