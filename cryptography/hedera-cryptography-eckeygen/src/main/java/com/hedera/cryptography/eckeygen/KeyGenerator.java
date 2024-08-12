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

import com.hedera.cryptography.pairings.signatures.api.GroupAssignment;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Operations for generating Bls Keys
 */
public interface KeyGenerator {

    /**
     * Generate a key pair (private key and public key) and return them and return them as byte arrays.
     * Index 0 corresponds to the private key.
     * Index 1 corresponds to the public key.
     *
     * @param groupAssignment  An int representing the {@link GroupAssignment} ordinal for selecting the elliptic curve group to use.
     * @return A byte array of size 2 with private key and public key each as byte[].
     */
    @Nullable
    byte[][] generateKeyPair(final int groupAssignment);

    /**
     * Generate a public key given an existent private key and return it as string.
     *
     * @param groupAssignment  An int representing the {@link GroupAssignment} ordinal for selecting the elliptic curve group to use.
     * @param sk  A byte array representing the private key.
     * @return A byte array representing the public key
     */
    @Nullable
    byte[] generatePublicKey(final int groupAssignment, @NonNull final byte[] sk);
}
