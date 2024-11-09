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
import com.hedera.cryptography.tss.api.TssShareTable;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A {@link TssShareTable} that maps a shareId to its participants {@link BlsPublicKey} for encryption.
 */
public class TssEncryptionKeyMap implements TssShareTable<BlsPublicKey> {
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
    private final BlsPublicKey[] tssKeyTable;
    /**
     *Sorted by value array of participantIds
     */
    private final long[] participantIds;

    /**
     * Constructor
     *
     * @param shareAllocationTable  Stores the {@code participant} that is the owner of each shareId in the protocol.
     * @param participantIds list of sorted by value participant ids
     * @param tssKeyTable Stores the {@link BlsPublicKey} of each {@code participant} in the protocol.
     */
    public TssEncryptionKeyMap(
            @NonNull final int[] shareAllocationTable,
            @NonNull final long[] participantIds,
            @NonNull final BlsPublicKey[] tssKeyTable) {
        this.shareAllocationTable = shareAllocationTable;
        this.tssKeyTable = tssKeyTable;
        this.participantIds = participantIds;
    }

    /**
     * Returns a tssShareId owner's {@link BlsPublicKey}.
     * If null, the participant does not belong to the directory.
     * @param shareId the numeric value of the share, not the index.
     * @return a BlsPublicKey belonging to the owner of the share.
     */
    @NonNull
    @Override
    public BlsPublicKey getForShareId(final int shareId) {
        if (shareId > shareAllocationTable.length || shareId <= 0) {
            throw new IllegalArgumentException("Invalid ShareId");
        }
        var shareOwner = shareAllocationTable[shareId - 1];
        return tssKeyTable[shareOwner];
    }

    /**
     * Given that participantId are long based, and we want to map it to a sequential index, to save storage
     * @param participantId the participant that wants to know the ids of its shares.
     * @return the shares owned by the participant {@code participantId}.
     */
    private int getParticipantIndex(final long participantId) {
        return Arrays.binarySearch(participantIds, participantId);
    }

    /**
     * Returns the shares owned by the participant {@code participantId }
     * @param participantId the participant querying for the info
     * @return the list of shares owned by the participant
     */
    @NonNull
    public List<Integer> getSharesForParticipantId(final long participantId) {
        List<Integer> shares = new ArrayList<>();
        int i = 0;
        final int participantIndex = getParticipantIndex(participantId);
        while (i < shareAllocationTable.length) {
            if (shareAllocationTable[i] == participantIndex) {
                shares.add(i + 1);
            }
            i++;
        }
        return shares;
    }
}
