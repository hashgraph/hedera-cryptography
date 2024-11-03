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

import static java.util.Objects.isNull;
import static java.util.Objects.requireNonNull;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.SignatureSchema;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.IntStream;

/**
 * Represents a directory of participants in a Threshold Signature Scheme (TSS).
 *<p>Each participant has an associated id (called {@code participantId}), shares count and a tss encryption public key.
 * It is responsibility of the user to assign each participant with a different deterministic integer representation.</p>
 *
 *<p>The current participant is represented by a {@code self} entry, and includes {@code participantId}'s id and the tss decryption private key.</p>
 *<p>The expected {@code participantId} is the unique {@link Long} identification for each participant executing the scheme.</p>
 * <pre>{@code
 * PairingPrivateKey tssDecryptionPrivateKey = ...;
 * List<PairingPublicKey> tssEncryptionPublicKeys = ...;
 * TssParticipantDirectory participantDirectory = TssParticipantDirectory.createBuilder()
 *     //id, tss private decryption key
 *     .self(0, persistentParticipantKey)
 *     //id, number of shares, tss public encryption key
 *     .withParticipant(0, 5, tssEncryptionPublicKeys.get(0))
 *     .withParticipant(1, 2, tssEncryptionPublicKeys.get(1))
 *     .withParticipant(2, 1, tssEncryptionPublicKeys.get(2))
 *     .withParticipant(3, 1, tssEncryptionPublicKeys.get(3))
 *     .withThreshold(5)
 *     .build(signatureScheme);
 * }</pre>
 *
 */
public final class TssParticipantDirectory implements TssEncryptionKeyResolver {
    /**
     * The currentParticipantId
     */
    private final Integer participantId;
    /**
     * a list of all participants tssShareIds in the directory.
     * The values are consecutive starting from 1 and must be sorted.
     */
    private final List<Integer> shareIds;
    /**
     * The list of owned Shares by the participant that created this directory.
     */
    private final List<Integer> ownedShareIds;
    /**
     * Stores the owner {@code participantId} of each TssShareId in the protocol.
     * index 0 represents share with id 1.
     * Shares are assigned sequentially.
     */
    private final Integer[] shareAllocationTable;
    /**
     * Stores the {@link BlsPublicKey} of each {@code participant} in the protocol.
     * There is one BlsPublicKey per participant
     */
    private final BlsPublicKey[] tssEncryptionPublicKeyTable;
    /**
     * The key to decrypt TssMessage parts intended for the participant that created this directory.
     * It is transient to assure it does not get serialized and exposed outside.
     */
    private final transient BlsPrivateKey tssDecryptionPrivateKey;
    /**
     * The minimum value that allows the recovery of Private and Public shares and that guarantees a valid signature.
     */
    private final int threshold;

    /**
     * Constructs a {@link TssParticipantDirectory}.
     *
     * @param participantId the participant owning this directory
     * @param shareIds list of participants ids
     * @param ownedShareIds the list of owned share IDs
     * @param shareAllocationTable share ids per participant
     * @param tssEncryptionPublicKeyTable participant IDs to public keys
     * @param tssDecryptionPrivateKey key to decrypt TssMessage parts intended
     * @param threshold  the threshold value for the TSS
     */
    public TssParticipantDirectory(
            @NonNull final Integer participantId,
            @NonNull final List<Integer> shareIds,
            @NonNull final List<Integer> ownedShareIds,
            @NonNull final Integer[] shareAllocationTable,
            @NonNull final BlsPublicKey[] tssEncryptionPublicKeyTable,
            @NonNull final BlsPrivateKey tssDecryptionPrivateKey,
            final int threshold) {
        this.participantId = participantId;
        this.shareIds = shareIds;
        this.ownedShareIds = ownedShareIds;
        this.shareAllocationTable = shareAllocationTable;
        this.tssEncryptionPublicKeyTable = tssEncryptionPublicKeyTable;
        this.tssDecryptionPrivateKey = tssDecryptionPrivateKey;
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
     * Returns the participant owning this directory.
     *
     * @return the participant owning this directory
     */
    public Integer getParticipantId() {
        return participantId;
    }

    /**
     * Returns the threshold value.
     *
     * @return the threshold value
     */
    public int getThreshold() {
        return threshold;
    }

    /**
     * Returns the shares owned by the participant represented as self.
     * This returns the numeric value of the share, not the index.
     * @return the shares owned by the participant represented as self.
     */
    @NonNull
    public List<Integer> getOwnedShareIds() {
        return ownedShareIds;
    }

    /**
     * Return the list of all the shareIds.
     * In this list, the first share has value of 1.
     * @return the list of all the shareIds
     */
    @NonNull
    public List<Integer> getShareIds() {
        return shareIds;
    }

    /**
     * Returns a tssShareId owner's {@link BlsPublicKey}.
     * If null, the participant does not belong to the directory.
     * @return a BlsPublicKey belonging to the owner of the share.
     */
    @Nullable
    @Override
    public BlsPublicKey resolveTssEncryptionKey(final int shareId) {
        var shareOwner = shareAllocationTable[shareId - 1];
        if (shareOwner != null) {
            return tssEncryptionPublicKeyTable[shareOwner];
        }
        return null;
    }

    /**
     * Returns the tssDecryptionPrivateKey.
     *
     * @return the tssDecryptionPrivateKey
     */
    public BlsPrivateKey tssDecryptionPrivateKey() {
        return tssDecryptionPrivateKey;
    }

    /**
     * A builder for creating {@link TssParticipantDirectory} instances.
     */
    public static class Builder {
        private SelfEntry selfEntry;
        private final Map<Integer, ParticipantEntry> participantEntries = new HashMap<>();
        private int threshold;

        private Builder() {}

        /**
         * Sets the self entry for the builder.
         *
         * @param participantId the participant unique {@link Long} representation
         * @param tssEncryptionPrivateKey the pairing private key used to decrypt tss share portions
         * @return the builder instance
         */
        @NonNull
        public Builder withSelf(final int participantId, @NonNull final BlsPrivateKey tssEncryptionPrivateKey) {
            if (selfEntry != null) {
                throw new IllegalArgumentException("There is already an for the current participant");
            }
            selfEntry = new SelfEntry(participantId, tssEncryptionPrivateKey);
            return this;
        }

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
         * Builds and returns a {@link TssParticipantDirectory} instance based on the provided entries and schema.
         *
         * @param schema the signatureSchema
         * @return the constructed ParticipantDirectory instance
         * @throws NullPointerException if schema is null
         * @throws IllegalStateException if there is no entry for the current participant
         * @throws IllegalStateException if there are no configured participants
         * @throws IllegalStateException if the threshold value is higher than the total shares
         */
        @NonNull
        public TssParticipantDirectory build(@NonNull final SignatureSchema schema) {
            Objects.requireNonNull(schema, "Schema must not be null");

            if (isNull(selfEntry)) {
                throw new IllegalStateException("There should be an entry for the current participant");
            }

            if (participantEntries.isEmpty()) {
                throw new IllegalStateException("There should be at least one participant in the protocol");
            }

            if (!participantEntries.containsKey(selfEntry.participantId())) {
                throw new IllegalStateException(
                        "The participant list does not contain a reference to the current participant");
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
            final Integer[] shareOwnershipTable = new Integer[totalShares];
            final BlsPublicKey[] tssEncryptionPublicKeyTable = new BlsPublicKey[maxId + 1];
            final List<Integer> ownedShares = new ArrayList<>();

            int currentIndex = 0;
            // Iteration of the sorted int representation to make sure we assign the shares deterministically.
            for (int participantId : participantIds) {
                final ParticipantEntry entry = participantEntries.get(participantId);
                tssEncryptionPublicKeyTable[participantId] = entry.tssEncryptionPublicKey;
                // Add the public encryption key for each participant id in the iteration.
                Arrays.fill(shareOwnershipTable, currentIndex, currentIndex + entry.shareCount(), participantId);
                if (participantId == selfEntry.participantId()) {
                    for (int i = currentIndex; i < currentIndex + entry.shareCount(); i++) {
                        ownedShares.add(i + 1);
                    }
                }
                currentIndex += entry.shareCount();
            }

            return new TssParticipantDirectory(
                    selfEntry.participantId,
                    shareIds,
                    List.copyOf(ownedShares),
                    shareOwnershipTable,
                    tssEncryptionPublicKeyTable,
                    selfEntry.tssEncryptionPrivateKey,
                    threshold);
        }
    }

    /**
     * Represents an entry for the participant executing the protocol, containing the ID and private key.
     * @param participantId identification of the participant
     */
    private record SelfEntry(int participantId, @NonNull BlsPrivateKey tssEncryptionPrivateKey) {
        /**
         * Constructor
         * @param participantId identification of the participant
         */
        public SelfEntry {
            requireNonNull(tssEncryptionPrivateKey, "tssEncryptionPrivateKey must not be null");
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
