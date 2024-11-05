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

/**
 * Threshold Signature Scheme Genesis Stage is the setup stage where all participants in the scheme collaborate to discover a shared polynomial.
 * <p>
 *  The contract of a :
 * <ul>
 *     <li>Generate {@link TssMessage} out of a random share</li>
 *     <li>Verify {@link TssMessage} out of a {@link TssParticipantDirectory}</li>
 *     <li>Obtain the list of {@link TssPrivateShare} out of a {@link TssParticipantDirectory}</li>
 *     <li>Obtain the list of {@link TssPublicShare} out of a {@link TssParticipantDirectory}</li>
 * </ul>
 * Produces a fresh ledgerId: as result of the aggregation af all obtained {@link TssPublicShare}
 */
public interface TssServiceGenesisStage extends TssServiceStage {

    /**
     * Generate a {@link TssMessage} for a {@code tssParticipantDirectory}, from a random private share.
     * This method can be used to bootstrap the protocol as it does not need the existence of a previous {@link TssPrivateShare}
     *
     * @param tssParticipantDirectory the participant directory that we should generate the message for
     * @return a {@link TssMessage} produced out of a random share.
     */
    @NonNull
    TssMessage generateTssMessage(@NonNull TssParticipantDirectory tssParticipantDirectory);

    /**
     * Verify that a {@link TssMessage} is valid.
     *
     * @param participantDirectory the participant directory used to generate the message
     * @param tssMessage the {@link TssMessage} to validate
     * @return true if the message is valid, false otherwise
     */
    boolean verifyTssMessage(@NonNull TssParticipantDirectory participantDirectory, @NonNull TssMessage tssMessage);
}
