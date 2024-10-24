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

package com.hedera.cryptography.tss.api;

import static java.util.Objects.requireNonNull;

import com.hedera.cryptography.bls.BlsPrivateKey;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Represents a secret portion of a shared key.
 * It's a BLS private key with an owner.
 *
 * @param shareId the share ID
 * @param privateKey the private key
 */
public record TssPrivateShare(@NonNull TssShareId shareId, @NonNull BlsPrivateKey privateKey) {
    /**
     * Constructor
     *
     * @param shareId the share ID
     * @param privateKey the private key
     */
    public TssPrivateShare {
        requireNonNull(shareId, "shareId must not be null");
        requireNonNull(privateKey, "privateKey must not be null");
    }

    /**
     * Creates a new instance.
     *
     * @param id id
     * @param privateKey the private key
     * @return a new {@link TssPrivateShare}
     */
    public static TssPrivateShare of(final int id, @NonNull final BlsPrivateKey privateKey) {
        requireNonNull(privateKey, "privateKey must not be null");
        if (id <= 0) {
            throw new IllegalArgumentException("id must be greater than 0");
        }
        return new TssPrivateShare(new TssShareId(privateKey.element().field().fromLong(id)), privateKey);
    }

    /**
     * Sign a message using the private share's key.
     * @param message the message to sign
     * @return the {@link TssShareSignature}
     */
    @NonNull
    public TssShareSignature sign(@NonNull final byte[] message) {
        return new TssShareSignature(this.shareId(), this.privateKey().sign(message));
    }
}
