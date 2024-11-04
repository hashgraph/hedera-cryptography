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
 * Threshold Signature Scheme dependant operations
 * <p>
 * Contract of TSS genesis stage:
 * <ul>
 *     <li>Generate TssMessages out of a private share</li>
 *     <li>Verify TssMessages out of a ParticipantDirectory and all previous {@link TssPublicShare}</li>
 * </ul>
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
