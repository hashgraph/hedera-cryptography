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
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * Contains mappings useful for the {@link com.hedera.cryptography.tss.api.TssParticipantDirectory}:
 * <ul>
 *  <li> Maps {@code ParticipantId}s to owned {@code shareId}s</li>
 *  <li> Maps {@code shareId}s to participant's {@code tssEncryptionPublicKey}s</li>
 *  </ul>
 */
public class TssParticipantAssigmentMapping {
    /**
     * Each index represents a participant.
     * Two values are stored per index:
     * <ul>
     *  <li>the first shareId belonging to the participant</li>
     *  <li>the number of shares assigned to that participant</li>
     *  </ul>
     */
    private final int[][] participantsShares;

    /**
     * Stores the {@code participant} index that is the owner of each shareId in the protocol.
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
     * A map that assigns an index to each participant in the directory
     */
    private final Map<Long, Integer> participantIds;

    /**
     * Constructor
     *
     * @param participantsShares  a table where each index is a participant and each value the first share assigned to it, and the second value the number-of-shares
     * @param shareAllocationTable  Stores the {@code participant} that is the owner of each shareId in the protocol.
     * @param participantIds list of sorted by value participant ids
     * @param tssKeyTable Stores the {@link BlsPublicKey} of each {@code participant} in the protocol.
     */
    public TssParticipantAssigmentMapping(
            @NonNull final int[][] participantsShares,
            @NonNull final int[] shareAllocationTable,
            @NonNull final Map<Long, Integer> participantIds,
            @NonNull final BlsPublicKey[] tssKeyTable) {
        this.participantsShares = participantsShares;
        ;
        this.shareAllocationTable = shareAllocationTable;
        this.tssKeyTable = tssKeyTable;
        this.participantIds = participantIds;
    }

    /**
     * Returns the {@code share} owner's {@link BlsPublicKey}.
     *
     * @param shareId the numeric value of the share, not the index.
     * @return a BlsPublicKey belonging to the owner of the share.
     * @throws IllegalArgumentException if the share is higher than the number of shares assigned or if is less or equals to 0
     */
    @NonNull
    public BlsPublicKey tssEncryptionKeyForShareId(final int shareId) {
        if (shareId <= 0 || shareId > shareAllocationTable.length) {
            throw new IllegalArgumentException("Invalid ShareId");
        }
        var shareOwner = shareAllocationTable[shareId - 1];
        return tssKeyTable[shareOwner];
    }

    /**
     * Returns the shares owned by the participant {@code participantId }
     * @param participantId the participant querying for the info.
     * @return the list of shares owned by the participant if it owns any share, an empty list if it doesn't or is not a participant in the scheme.
     */
    @NonNull
    public List<Integer> getSharesForParticipantId(final long participantId) {
        final Integer participantIndex = participantIds.get(participantId);
        if (participantIndex == null) {
            return List.of();
        }
        return IntStream.range(
                        participantsShares[participantIndex][0],
                        participantsShares[participantIndex][0] + participantsShares[participantIndex][1])
                .boxed()
                .toList();
    }

    /**
     * Return the list of all the shareIds.
     * In this list, the first share has value of 1.
     * This returns the numeric value of the share, not the index.
     * @return the list of all the shareIds
     */
    @NonNull
    public List<Integer> getShareIds() {
        return IntStream.rangeClosed(1, shareAllocationTable.length).boxed().toList();
    }
}
