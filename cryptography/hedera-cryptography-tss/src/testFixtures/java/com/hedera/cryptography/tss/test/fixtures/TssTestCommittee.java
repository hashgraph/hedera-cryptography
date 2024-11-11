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

package com.hedera.cryptography.tss.test.fixtures;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssParticipantPrivateInfo;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.stream.IntStream;

/**
 * For testing purposes, where we are executing code in behalf of more than one participant of the protocol,
 * A committee is able to build the {@link TssParticipantDirectory},
 * and the {@link TssParticipantPrivateInfo} for  one, or a selected number of participants given their ids.
 *
 * @param size the total size of the committee.
 * @param sharesPerParticipant how many shares are assigned to each participant
 * @param keys an array of keys where the key[0] belongs to the first participant and so on.
 */
public record TssTestCommittee(int size, int sharesPerParticipant, @NonNull BlsPrivateKey... keys) {

    public int threshold() {
        return (size * sharesPerParticipant + 2) / 2;
    }
    /**
     * Retrieves the selected directory
     * @return the selected participant's directory
     */
    @NonNull
    public TssParticipantDirectory participantDirectory() {
        final var directoryBuilder = TssParticipantDirectory.createBuilder().withThreshold(this.threshold());
        for (int i = 0; i < this.size(); i++) {
            directoryBuilder.withParticipant(i, this.sharesPerParticipant(), this.keys()[i].createPublicKey());
        }
        return directoryBuilder.build();
    }

    /**
     * Returns the private info for all participants.
     * @return the private info for all participants
     */
    @NonNull
    public List<TssParticipantPrivateInfo> allPrivateInfo() {
        return IntStream.range(0, this.size())
                .mapToObj(i -> new TssParticipantPrivateInfo(i, this.keys()[i]))
                .toList();
    }

    /**
     *
     * @param participantId participant id
     * @return the private info of {@code participantId}
     */
    @NonNull
    public TssParticipantPrivateInfo privateInfoOf(final int participantId) {
        return new TssParticipantPrivateInfo(participantId, this.keys()[participantId]);
    }
}
