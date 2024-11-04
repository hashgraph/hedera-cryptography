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

package com.hedera.cryptography.tss.extensions;

import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.tss.api.TssKeyTable;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An TssEncryptionEncryption Table.
 * It maps a shareId to its participants {@link BlsPublicKey} for encryption.
 */
public class TssKeyTableImpl<T> implements TssKeyTable<T> {

    /**
     * Stores the {@code participant} that is the owner of each shareId in the protocol.
     * Index 0 represents shareId 1 and so on.
     * Shares are assigned sequentially.
     */
    private final int[] shareAllocationTable;

    /**
     * Stores the {@link BlsPublicKey} of each {@code participant} in the protocol.
     * There is one BlsPublicKey per participant
     */
    private final T[] tssKeyTable;

    /**
     * Constructor
     *
     * @param shareAllocationTable  Stores the {@code participant} that is the owner of each shareId in the protocol.
     * @param tssKeyTable Stores the {@link BlsPublicKey} of each {@code participant} in the protocol.
     */
    public TssKeyTableImpl(final int[] shareAllocationTable, final T[] tssKeyTable) {
        this.shareAllocationTable = shareAllocationTable;
        this.tssKeyTable = tssKeyTable;
    }

    /**
     * Returns a tssShareId owner's {@link BlsPublicKey}.
     * If null, the participant does not belong to the directory.
     * @param shareId the numeric value of the share, not the index.
     * @return a BlsPublicKey belonging to the owner of the share.
     */
    @NonNull
    @Override
    public T resolveKeyForShare(final int shareId) {
        if (shareId > shareAllocationTable.length || shareId <= 0) {
            throw new IllegalArgumentException("Invalid ShareId");
        }
        var shareOwner = shareAllocationTable[shareId - 1];
        return tssKeyTable[shareOwner];
    }
}
