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

import static java.util.Objects.requireNonNull;

import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.tss.extensions.TssEncryptionKeyMap;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * Represents a public directory of participants in a Threshold Signature Scheme (TSS).
 *<p>Each participant has an {@code participantId}, an assigned number of shares and a {@code tssEncryptionPublicKey}.
 *<p>The directory will come up with a consecutive integer representation of each participant of the scheme.
 *
 *<p>The expected {@code participantId} is the unique {@link Long} identification for each participant executing the scheme.</p>
 * <pre>{@code
 * List<PairingPublicKey> tssEncryptionPublicKeys = ...; //retrieve all the participant's keys from whatever storage
 * TssParticipantDirectory participantDirectory = TssParticipantDirectory.createBuilder()
 *     //participantId, number-of-shares, tssEncryptionPublicKey
 *     .withParticipant(0, 5, tssEncryptionPublicKeys.get(0))
 *     .withParticipant(1, 2, tssEncryptionPublicKeys.get(1))
 *     .withParticipant(2, 1, tssEncryptionPublicKeys.get(2))
 *     .withParticipant(3, 1, tssEncryptionPublicKeys.get(3))
 *     .withThreshold(6)
 *     .build();
 * }</pre>
 */
public final class TssParticipantDirectory implements TssShareTable<BlsPublicKey> {
    /**
     * A list of all assigned {@code shareIds} in the directory. The values are sorted, consecutive and starting from 1.
     * This contains the numeric value of the share, not the index. ShareId 0 does not exist and is reserved.
     */
    private final List<Integer> shareIds;
    /**
     * In directory used to generate TssMessages, the {@code threshold} defines the number of shares-of-shares that will be created to perform shamir-secret-sharing.
     * In a directory used to validate and latter process TssMessages, the {@code threshold} value is the minimum number of messages that assures the correct recovery of
     * {@link TssPrivateShare} and {@link TssPublicShare}.
     * While executing the scheme there exist up to two threshold values:
     *   a candidate threshold which is used for generating new sharing.
     *   and, a current threshold which is used for validating existing committee and assure the correct recovery of the secrets/public keys.
     * In any case, to which of those of this property refers to, depends on whether the directory represents a candidate directory or an adopted one.
     */
    private final int threshold;

    /**
     * Stores the {@link BlsPublicKey} of each {@code ShareId} in the protocol.
     */
    private final TssEncryptionKeyMap tssEncryptionTable;

    /**
     * Constructs a {@link TssParticipantDirectory}.
     *
     * @param shareIds list of participants ids
     * @param tssEncryptionTable share to participant public keys table
     * @param threshold  the threshold value for the TSS
     */
    private TssParticipantDirectory(
            @NonNull final List<Integer> shareIds,
            @NonNull final TssEncryptionKeyMap tssEncryptionTable,
            final int threshold) {
        this.shareIds = List.copyOf(shareIds);
        this.tssEncryptionTable = tssEncryptionTable;
        this.threshold = threshold;
    }

    /**
     * Creates a new Builder for constructing a {@link TssParticipantDirectory}.
     *
     * @return a new Builder instance
     */
    @NonNull
    public static Builder createBuilder() {
        return new Builder();
    }

    /**
     * Returns the threshold value.
     * In an originating directory, the {@code threshold} value is the minimum number of messages that assures the correct recovery of
     * {@link TssPrivateShare} and {@link TssPublicShare}.
     * In a target directory the {@code threshold} defines the number of shares-of-shares that will be created to perform shamir-secret-sharing.
     * @return the threshold value
     */
    public int getThreshold() {
        return threshold;
    }

    /**
     * Return the list of all the shareIds.
     * In this list, the first share has value of 1.
     * This returns the numeric value of the share, not the index.
     * @return the list of all the shareIds
     */
    @NonNull
    public List<Integer> getShareIds() {
        return shareIds;
    }

    /**
     * The list of participant's owned shareIds.
     * This returns the numeric value of the share, not the index.
     * @param participantId the participant that wants to know the ids of its shares.
     * @return the shares owned by the participant {@code participantId}.
     */
    @NonNull
    public List<Integer> ownedShares(long participantId) {
        int pi = getParticipantIndex(participantId);
        return tssEncryptionTable.getSharesForParticipantId(pi);
    }

    /**
     * Given that participantId are long based, and we want to map it to a sequential index, to save storage
     * @param participantId the participant that wants to know the ids of its shares.
     * @return the shares owned by the participant {@code participantId}.
     */
    private int getParticipantIndex(final long participantId) {
        return (int)
                participantId; // FUTURE-WORK: #16481 strengthen this mapping of participantId to a sequential index, to
        // save storage
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
        return tssEncryptionTable.getForShareId(shareId);
    }

    /**
     * A builder for creating {@link TssParticipantDirectory} instances.
     */
    public static class Builder {
        private final Map<Integer, ParticipantEntry> participantEntries = new HashMap<>();
        private int threshold;

        private Builder() {}

        /**
         * Sets the threshold value for the TSS.
         *
         * @param threshold the threshold value
         * @return the builder instance
         * @throws IllegalArgumentException if threshold is less than or equals to 0
         */
        @NonNull
        public Builder withThreshold(final int threshold) {
            if (threshold <= 0) {
                throw new IllegalArgumentException("Invalid threshold: " + threshold);
            }
            this.threshold = threshold;
            return this;
        }

        /**
         * Adds a participant entry to the builder.
         *
         * @param participantId the participant unique {@link Long} representation
         * @param numberOfShares the number of shares
         * @param tssEncryptionPublicKey the pairing public key used to encrypt tss share portions designated to the participant represented by this entry
         * @return the builder instance
         * @throws IllegalArgumentException if participantId was previously added.
         */
        @NonNull
        public Builder withParticipant(
                final Integer participantId,
                final int numberOfShares,
                @NonNull final BlsPublicKey tssEncryptionPublicKey) {
            if (participantEntries.containsKey(participantId))
                throw new IllegalArgumentException(
                        "Participant with id " + participantId + " was previously added to the directory");

            participantEntries.put(participantId, new ParticipantEntry(numberOfShares, tssEncryptionPublicKey));
            return this;
        }

        /**
         * Builds and returns a {@link TssParticipantDirectory} instance based on the provided entries and signatureSchema.
         *
         * @return the constructed ParticipantDirectory instance
         * @throws NullPointerException if signatureSchema is null
         * @throws IllegalStateException if there is no entry for the current participant
         * @throws IllegalStateException if there are no configured participants
         * @throws IllegalStateException if the threshold value is higher than the total shares
         */
        @NonNull
        public TssParticipantDirectory build() {

            if (participantEntries.isEmpty()) {
                throw new IllegalStateException("There should be at least one participant in the protocol");
            }

            // Get the total number of shares of to distribute in the protocol
            final int totalShares = participantEntries.values().stream()
                    .map(ParticipantEntry::shareCount)
                    .reduce(0, Integer::sum);

            final List<Integer> participantIds =
                    participantEntries.keySet().stream().sorted().toList();
            final Integer maxId =
                    participantIds.stream().max(Integer::compareTo).orElse(participantEntries.size());
            if (threshold > totalShares) {
                throw new IllegalStateException("Threshold exceeds the number of shares");
            }

            final List<Integer> shareIds =
                    IntStream.rangeClosed(1, totalShares).boxed().toList();
            final int[] shareOwnershipTable = new int[totalShares];
            final BlsPublicKey[] tssEncryptionPublicKeyTable = new BlsPublicKey[maxId + 1];

            int currentIndex = 0;
            // Iteration of the sorted int representation to make sure we assign the shares deterministically.
            for (int participantId : participantIds) {
                final ParticipantEntry entry = participantEntries.get(participantId);
                tssEncryptionPublicKeyTable[participantId] = entry.tssEncryptionPublicKey;
                // Add the public encryption key for each participant id in the iteration.
                Arrays.fill(shareOwnershipTable, currentIndex, currentIndex + entry.shareCount(), participantId);
                currentIndex += entry.shareCount();
            }

            return new TssParticipantDirectory(
                    shareIds, new TssEncryptionKeyMap(shareOwnershipTable, tssEncryptionPublicKeyTable), threshold);
        }
    }

    /**
     * Represents an entry for a participant, containing the ID, share count, and public key.
     * @param shareCount number of shares owned by the participant represented by this record
     * @param tssEncryptionPublicKey the pairing public key used to encrypt tss share portions designated to the participant represented by this record
     */
    private record ParticipantEntry(int shareCount, @NonNull BlsPublicKey tssEncryptionPublicKey) {
        /**
         * Constructor
         *
         * @param shareCount number of shares owned by the participant represented by this record
         * @param tssEncryptionPublicKey the pairing public key used to encrypt tss share portions designated to the participant represented by this record
         */
        public ParticipantEntry {
            requireNonNull(tssEncryptionPublicKey, "tssEncryptionPublicKey must not be null");
        }
    }
}
