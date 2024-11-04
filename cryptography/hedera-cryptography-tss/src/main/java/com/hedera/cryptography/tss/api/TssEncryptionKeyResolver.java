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

import com.hedera.cryptography.bls.BlsPublicKey;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Allows to obtain a {@link BlsPublicKey} given a shareId
 */
public interface TssEncryptionKeyResolver {
    /**
     * Obtains a {@link BlsPublicKey} given a shareId.
     * Null if the shareId is not present or its owner cannot be found.
     * @param tssShareId an integer representing the shareId starting in 1.
     * @return the BlsPublicKey of the participant that owns the tssShareId.
     * @throws IllegalArgumentException if the shareId less or equals to 0 or if it is higher than the total assigned shares
     */
    @NonNull
    BlsPublicKey resolveTssEncryptionKey(int tssShareId);
}
