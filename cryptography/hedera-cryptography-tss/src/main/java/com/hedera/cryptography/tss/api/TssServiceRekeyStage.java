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

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.List;

/**
 * Threshold Signature Scheme rekey Stage is the stage where all participants in the scheme re distributes their key material and comes up with a set newly created keys
 * that aggregated produces the same ledgerId.
 * <p>
 * Contract of TSS rekey stage:
 * <ul>
 *     <li>Generate {@link TssMessage} out of a {@link TssPrivateShare}</li>
 *     <li>Verify {@link TssMessage} out of a {@link TssParticipantDirectory},
 *        and all previous {@link TssPublicShare}</li>
 *     <li>Obtain the list of {@link TssPrivateShare} out of a {@link TssParticipantDirectory}</li>
 *     <li>Obtain the list of {@link TssPublicShare} out of a {@link TssParticipantDirectory}</li>
 * </ul>
 * The result of the aggregation af all obtained {@link TssPublicShare} retrieves the same previously generated ledgerId
 */
public interface TssServiceRekeyStage extends TssServiceStage {
    /**
     * Generate a {@link TssMessage} for a {@code tssParticipantDirectory}, for the specified {@link TssPrivateShare}.
     *
     * @param tssParticipantDirectory the participant directory that we should generate the message for
     * @param privateShare       the secret to use for generating new keys
     * @return a TssMessage for the requested share.
     */
    @NonNull
    TssMessage generateTssMessage(
            @NonNull TssParticipantDirectory tssParticipantDirectory, @NonNull TssPrivateShare privateShare);

    /**
     * Verify that a {@link TssMessage} is valid.
     *
     * @param participantDirectory the participant directory used to generate the message
     * @param publicShares if available, the list of {@link TssPublicShare} that contains the local public share corresponding to the private share this message was generated from
     * @param tssMessage the {@link TssMessage} to validate
     * @return true if the message is valid, false otherwise
     */
    boolean verifyTssMessage(
            @NonNull TssParticipantDirectory participantDirectory,
            @Nullable List<TssPublicShare> publicShares,
            @NonNull TssMessage tssMessage);
}
