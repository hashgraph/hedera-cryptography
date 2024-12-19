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

package com.hedera.cryptography.tss.test.fixtures.beaver;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssParticipantPrivateInfo;
import com.hedera.cryptography.utils.test.fixtures.Pair;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A builder class for creating a Threshold Signature Scheme (TSS) participant directory with configurable committee
 * parameters. This builder allows for the creation of committees with specific sizes, share distributions, and
 * cryptographic settings.
 *
 * <p>The builder supports two main ways of configuring the committee:
 * <ul>
 *   <li>Using a fixed committee size with equal shares per participant</li>
 *   <li>Using a custom share distribution where each participant can have a different number of shares</li>
 * </ul>
 *
 * <p>Example usage with fixed committee size:
 * <pre>{@code
 * CommitteeBuilder builder = new CommitteeBuilder(beaver)
 *     .withCommitteeSize(3, 2)      // 3 participants, 2 shares each
 *     .withThreshold(4)             // Threshold of 4 shares needed
 *     .randomKeys()                 // Generate random BLS keys
 *     .withSchema(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);
 * TssParticipantDirectory directory = builder.build();
 * }</pre>
 *
 * <p>Example usage with custom share distribution:
 * <pre>{@code
 * CommitteeBuilder builder = new CommitteeBuilder(beaver)
 *     .withShareDistribution(
 *         Pair.of(0, 3),  // Participant 0 gets 3 shares
 *         Pair.of(1, 2),  // Participant 1 gets 2 shares
 *         Pair.of(2, 1)   // Participant 2 gets 1 share
 *     )
 *     .withKeys(predefinedKeys)
 *     .withThreshold(4);
 * TssParticipantDirectory directory = builder.build();
 * }</pre>
 */
final public class CommitteeBuilder {
    private final Beaver beaver;
    private boolean randomKeys = false;
    private List<Pair<Integer, Integer>> customShareDistribution;
    private List<Integer> absentParticipants;
    private BlsPrivateKey[] keys;
    private SignatureSchema schema;
    int numberParticipants = 0;
    int customNumberParticipants = 0;
    int sharesPerParticipant = 0;
    int customThreshold = 0;
    int numberOfShares = -1;

    /**
     * Constructs a new CommitteeBuilder instance.
     *
     * @param beaver The Beaver instance to associate with this builder
     */
    CommitteeBuilder(final Beaver beaver) {
        this.beaver = beaver;
    }

    /**
     * Enables the generation of random BLS private keys for all participants. Cannot be used if keys have already been
     * set using {@link #withKeys(BlsPrivateKey[])}.
     *
     * @return this builder instance
     * @throws IllegalStateException if keys have already been set
     */
    @NonNull
    public CommitteeBuilder randomKeys() {
        if (keys != null) {
            throw new IllegalStateException("Cannot enable random keys when keys are set");
        }
        randomKeys = true;
        return this;
    }

    /**
     * Sets predefined BLS private keys for all participants. Cannot be used if random key generation has been enabled
     * using {@link #randomKeys()}.
     *
     * @param keys Array of BLS private keys for participants
     * @return this builder instance
     * @throws NullPointerException  if keys is null
     * @throws IllegalStateException if random keys generation is enabled
     */
    @NonNull
    public CommitteeBuilder withKeys(@NonNull final BlsPrivateKey[] keys) {
        Objects.requireNonNull(keys, "Keys cannot be null");
        if (randomKeys) {
            throw new IllegalStateException("Cannot set keys when random keys are enabled");
        }
        this.keys = Arrays.copyOf(keys, keys.length);
        return this;
    }

    /**
     * Sets the committee size with equal share distribution among participants. Cannot be used if committee size or
     * share distribution has already been set.
     *
     * @param numberParticipants   Number of participants in the committee
     * @param sharesPerParticipant Number of shares assigned to each participant
     * @return this builder instance
     * @throws IllegalArgumentException if numberParticipants or sharesPerParticipant is less than 1
     * @throws IllegalStateException    if committee size has already been set
     */
    @NonNull
    public CommitteeBuilder withCommitteeSize(final int numberParticipants, final int sharesPerParticipant) {
        if (numberParticipants < 1) {
            throw new IllegalArgumentException("Number of participants must be greater than 0");
        }
        if (sharesPerParticipant < 1) {
            throw new IllegalArgumentException("Shares per participant must be greater than 0");
        }
        if (this.customNumberParticipants != 0 || this.sharesPerParticipant != 0) {
            throw new IllegalStateException("Cannot set committee size when it is already set");
        }
        this.customNumberParticipants = numberParticipants;
        this.sharesPerParticipant = sharesPerParticipant;

        return this;
    }

    /**
     * Sets a custom distribution of shares among participants. Each pair contains a participant ID and the number of
     * shares assigned to that participant.
     *
     * @param distributions Array of participant ID and share count pairs
     * @return this builder instance
     * @throws NullPointerException if distributions is null
     */
    @NonNull
    public CommitteeBuilder withShareDistribution(@NonNull final Pair<Integer, Integer>... distributions) {
        Objects.requireNonNull(distributions, "Distributions cannot be null");
        customShareDistribution = List.of(distributions);
        return this;
    }

    /**
     * Specifies which participants should be marked as absent in the committee. Absent participants will be excluded
     * from the final directory.
     *
     * @param participants Array of participant IDs to mark as absent
     * @return this builder instance
     * @throws NullPointerException if participants is null
     */
    @NonNull
    public CommitteeBuilder withAbsentParticipants(@NonNull final Integer... participants) {
        Objects.requireNonNull(participants, "Participants cannot be null");
        absentParticipants = List.of(participants);
        return this;
    }

    /**
     * Sets the threshold number of shares required for signature reconstruction. If not set, defaults to
     * (numberOfShares + 2) / 2.
     *
     * @param threshold Minimum number of shares required for signature reconstruction
     * @return this builder instance
     * @throws IllegalArgumentException if threshold is less than 1
     */
    @NonNull
    public CommitteeBuilder withThreshold(final int threshold) {
        if (threshold < 1) {
            throw new IllegalArgumentException("Threshold must be greater than 0");
        }
        customThreshold = threshold;
        return this;
    }

    /**
     * Sets the signature scheme parameters including the curve and group assignment. If not set, defaults to ALT_BN128
     * curve with SHORT_SIGNATURES group assignment.
     *
     * @param curve           The elliptic curve to use for the signature scheme
     * @param groupAssignment The group assignment strategy for signatures
     * @return this builder instance
     * @throws NullPointerException if curve or groupAssignment is null
     */
    @NonNull
    public CommitteeBuilder withSchema(@NonNull final Curve curve, @NonNull final GroupAssignment groupAssignment) {
        this.schema = SignatureSchema.create(curve, groupAssignment);
        return this;
    }

    /**
     * Builds and returns the TssParticipantDirectory based on the configured parameters.
     *
     * @return A new TssParticipantDirectory instance
     * @throws IllegalStateException if required parameters are not set
     */
    @NonNull
    TssParticipantDirectory build() {
        if (customNumberParticipants == 0 || sharesPerParticipant == 0) {
            throw new IllegalStateException("Committee size must be set");
        }
        if (schema == null) {
            schema = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);
        }
        if (randomKeys) {
            keys = new BlsPrivateKey[customNumberParticipants];
            for (int i = 0; i < customNumberParticipants; i++) {
                keys[i] = BlsPrivateKey.create(schema, beaver.getRng());
            }
        } else if (keys == null) {
            throw new IllegalStateException("Keys must be set");
        }

        if (customNumberParticipants > 0 && sharesPerParticipant > 0) {
            numberParticipants = customNumberParticipants;
            numberOfShares = customNumberParticipants * sharesPerParticipant;
            final var threshold = customThreshold == 0 ? (numberOfShares + 2) / 2 : customThreshold;
            final var directoryBuilder = TssParticipantDirectory.createBuilder().withThreshold(threshold);

            for (int i = 0; i < customNumberParticipants; i++) {
                if (absentParticipants != null && absentParticipants.contains(i)) {
                    continue;
                }
                directoryBuilder.withParticipant(i, sharesPerParticipant, keys[i].createPublicKey());
            }
            return directoryBuilder.build();
        } else if (customShareDistribution != null) {
            numberParticipants = customShareDistribution.size();
            numberOfShares = customShareDistribution.stream().mapToInt(Pair::right).sum();
            final var threshold = customThreshold == 0 ? (numberOfShares + 2) / 2 : customThreshold;
            final var directoryBuilder = TssParticipantDirectory.createBuilder().withThreshold(threshold);

            for (int i = 0; i < customShareDistribution.size(); i++) {
                if (absentParticipants != null && absentParticipants.contains(i)) {
                    continue;
                }
                final var distribution = customShareDistribution.get(i);
                directoryBuilder.withParticipant(distribution.left(), distribution.right(), keys[i].createPublicKey());
            }
            return directoryBuilder.build();
        } else {
            throw new IllegalStateException("Committee size must be set");
        }

    }

    /**
     * Returns the builder to the parent Beaver instance for method chaining.
     *
     * @return The parent Beaver instance
     */
    @NonNull
    public Beaver and() {
        beaver.setCommitteeBuilder(this);
        return beaver;
    }

    /**
     * Returns the array of BLS private keys configured for this committee.
     *
     * @return Array of BLS private keys
     */
    @NonNull
    BlsPrivateKey[] getKeys() {
        return keys;
    }

    /**
     * Returns the total number of shares distributed across all participants.
     *
     * @return Total number of shares
     */
    int getNumberOfShares() {
        return numberOfShares;
    }

    /**
     * Returns the configured signature scheme.
     *
     * @return The SignatureSchema instance
     */
    @NonNull
    SignatureSchema getSchema() {
        if (schema == null) {
            throw new IllegalStateException("Signature schema not set");
        }
        return schema;
    }

    /**
     * Returns the total number of participants in the committee.
     *
     * @return Number of participants
     */
    int getNumberParticipants() {
        return numberParticipants;
    }

    /**
     * Returns the private info of {@code participantId}
     *
     * @param participantId participant participantId
     * @return the private info of {@code participantId}
     */
    @NonNull
    TssParticipantPrivateInfo privateInfoOf(final int participantId) {
        if (keys == null) {
            throw new IllegalStateException("Keys must not set yet");
        }
        return new TssParticipantPrivateInfo(participantId, this.keys[participantId]);
    }
}
