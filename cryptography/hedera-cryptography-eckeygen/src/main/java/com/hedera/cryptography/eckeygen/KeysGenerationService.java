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

import com.google.protobuf.ByteString;
import com.hedera.cryptography.pairings.signatures.api.SignatureSchema;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Base64;
import java.util.Objects;

/**
 * Service class for creating Bls Keys in base64 encoding
 */
public class KeysGenerationService {

    private final KeyGenerator keyGen;
    private final SignatureSchema signatureSchema;

    /**
     * Creates a new instance of this service.
     *
     * @param signatureSchema  Elliptic Curve predefined configuration for this utility
     * @param keyGen a Bls Key Generator
     */
    public KeysGenerationService(@NonNull final SignatureSchema signatureSchema, @NonNull final KeyGenerator keyGen) {
        this.keyGen = Objects.requireNonNull(keyGen, "keyGen must not be null");
        this.signatureSchema = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
    }

    /**
     * Encodes a byte array to a Base64 string.
     *
     * @param byteArray the byte array to encode
     * @return the Base64 encoded string
     */
    @NonNull
    private static String encodeToBase64(@NonNull final byte[] byteArray) {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(Objects.requireNonNull(byteArray, "byteArray must not be null"));
    }

    /**
     * Decodes a byte array to a Base64 string.
     * @param base64 the base64 string to decode
     * @return the decoded byte[] represented by the String
     */
    @NonNull
    private static byte[] decodeFromBase64(@NonNull final String base64) {
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(Objects.requireNonNull(base64, "base64 string must not be null"));
    }

    /**
     * Generates a Key Pair (private and public keys) and returns them as Base64 Java Strings
     *
     * @return A String Array of two elements containing the base64 string of the private key on the first element and the public key in the second.
     *
     */
    @NonNull
    public String[] generateBase64KeyPair() {
        byte[][] output = new byte[2][];
        if (keyGen.generateKeyPair(signatureSchema.getGroupAssignment().ordinal(), output) != 0) {
            throw new KeysServiceException("KeyPair generation failed");
        }

        ByteString prefix = ByteString.copyFrom(new byte[] {signatureSchema.getIdByte(), 0, 0});
        ByteString sk = ByteString.copyFrom(output[0]);
        ByteString pk = ByteString.copyFrom(output[1]);
        return new String[] {
            encodeToBase64(prefix.concat(sk).toByteArray()),
            encodeToBase64(prefix.concat(pk).toByteArray())
        };
    }

    /**
     * Generates a public key given an existent private key and return it as Base64 Java Strings
     *
     * @param base64PrivateKey Elliptic Curve predefined configuration for this utility
     * @return A String containing the base64 representation of the public key .
     */
    @NonNull
    public String generateBase64KPublicKey(@NonNull final String base64PrivateKey) {
        byte[] skBytes =
                decodeFromBase64(Objects.requireNonNull(base64PrivateKey, "base64PrivateKey must not be null"));

        ByteString prefix = ByteString.copyFrom(new byte[] {signatureSchema.getIdByte(), 0, 0});
        ByteString sk = ByteString.copyFrom(skBytes);
        byte[] pkBytes = keyGen.generatePublicKey(
                signatureSchema.getGroupAssignment().ordinal(),
                sk.substring(prefix.size()).toByteArray());
        return encodeToBase64(prefix.concat(ByteString.copyFrom(pkBytes)).toByteArray());
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
