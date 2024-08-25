/*
 * Copyright (C) 2022-2024 Hedera Hashgraph, LLC
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

package com.hedera.cryptography.altbn128.common;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/** Static utility hashing operations */
public final class HashUtils {


    /**
     * Computes SHA 256 hash
     *
     * @param message message to hash
     * @return 256-bit hash
     */
    @NonNull
    public static byte[] computeSha256(final @NonNull byte[] message) {
        Objects.requireNonNull(message, "message must not be null");
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(message);
            return digest.digest();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Could not hash message", e);
        }
    }
}
