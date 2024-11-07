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
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.stream.IntStream;

/**
 * For testing purposes, where we are executing code in behalf of more than one participant of the protocol A distribute
 * key generation committee is able to build the directory for all, one, or a selected number of participants given its
 * id.
 *
 * @param size the total size of the committee. First participant is p1.
 * @param keys an array of keys where the key[0] belongs to the first participant and so on.
 */
public record DkgCommittee(int size, int sharesPerParticipant, @NonNull BlsPrivateKey... keys) {

    public int threshold() {
        return (size * sharesPerParticipant + 2) / 2;
    }
    /**
     * Retrieves the selected directory
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @param participantId participant id
     * @return the selected participant's directory
     */
    @NonNull
    public TssParticipantDirectory directoryFor(
            @NonNull final SignatureSchema signatureSchema, final int participantId) {
        var directoryBuilder = TssParticipantDirectory.createBuilder()
                .withThreshold(this.threshold())
                .withSelf(participantId, this.keys()[participantId - 1]);
        for (int i = 0; i < this.size(); i++) {
            directoryBuilder.withParticipant(i + 1, this.sharesPerParticipant(), this.keys()[i].createPublicKey());
        }
        return directoryBuilder.build(signatureSchema);
    }

    /**
     * Retrieves all directories in the committee
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @return a list of directories from the committee
     */
    public List<TssParticipantDirectory> allDirectories(final SignatureSchema signatureSchema) {
        return IntStream.rangeClosed(1, size())
                .mapToObj(i -> directoryFor(signatureSchema, i))
                .toList();
    }
}
