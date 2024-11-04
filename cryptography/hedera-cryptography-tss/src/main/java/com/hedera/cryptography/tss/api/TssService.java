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

import com.hedera.cryptography.bls.SignatureSchema;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.List;

/**
 * A Threshold Signature Scheme Service.
 * <p>
 * Contract of TSS:
 * <ul>
 *     <li>Generate TssMessages out of PrivateShares</li>
 *     <li>Verify TssMessages out of a ParticipantDirectory</li>
 *     <li>Obtain PrivateShares out of TssMessages for each owned share</li>
 *     <li>Obtain PublicShares out of TssMessages for each share</li>
 * </ul>
 * @implNote an instance of the service would require a source of randomness {@link java.util.Random}, and a{@link SignatureSchema}
 */
public interface TssService {

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
     * @param tssMessage the {@link TssMessage} to validate
     * @return true if the message is valid, false otherwise
     */
    boolean verifyTssMessage(@NonNull TssParticipantDirectory participantDirectory, @NonNull TssMessage tssMessage);

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

    /**
     * Compute all private shares that belongs to this participant from a threshold minimum number of {@link TssMessage}s.
     * It is the responsibility of the caller to ensure that the list of validTssMessages meets the required threshold.
     *
     * @param participantDirectory the pending participant directory that we should generate the private share for
     * @param validTssMessages the TSS messages to extract the private shares from. They must be previously validated.
     * @return a sorted by sharedId list of private shares the current participant owns.
     * @throws IllegalStateException if there aren't enough messages to meet the threshold
     */
    @NonNull
    List<TssPrivateShare> obtainPrivateShares(
            @NonNull TssParticipantDirectory participantDirectory, @NonNull List<TssMessage> validTssMessages);

    /**
     * Compute all public shares for all the participants in the scheme.
     *
     * @param participantDirectory the participant directory that we should generate the public shares for
     * @param validTssMessages the {@link TssMessage}s to extract the public shares from. They must be previously validated.
     * @return a sorted by the sharedId list of public shares.
     * @throws IllegalStateException if there aren't enough messages to meet the threshold
     */
    @NonNull
    List<TssPublicShare> obtainPublicShares(
            @NonNull TssParticipantDirectory participantDirectory, @NonNull List<TssMessage> validTssMessages);
}
