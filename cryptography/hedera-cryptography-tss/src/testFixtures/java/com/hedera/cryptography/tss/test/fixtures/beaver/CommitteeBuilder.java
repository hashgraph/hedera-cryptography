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
import com.hedera.cryptography.utils.test.fixtures.Pair;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class CommitteeBuilder {
    private final Beaver beaver;
    private boolean randomKeys = false;
    private List<Pair<Integer, Integer>> customShareDistribution;
    private List<Integer> absentParticipants;
    private BlsPrivateKey[] keys;
    int numberParticipants = 0;
    int sharesPerParticipant = 0;
    int customThreshold = 0;

    CommitteeBuilder(final Beaver beaver) {
        this.beaver = beaver;
    }

    @NonNull
    public CommitteeBuilder randomKeys() {
        if (keys != null) {
            throw new IllegalStateException("Cannot enable random keys when keys are set");
        }
        randomKeys = true;
        return this;
    }

    @NonNull
    public CommitteeBuilder withKeys(@NonNull final BlsPrivateKey[] keys) {
        Objects.requireNonNull(keys, "Keys cannot be null");
        if (randomKeys) {
            throw new IllegalStateException("Cannot set keys when random keys are enabled");
        }
        this.keys = Arrays.copyOf(keys, keys.length);
        return this;
    }

    @NonNull
    public CommitteeBuilder withCommitteeSize(final int numberParticipants, final int sharesPerParticipant) {
        if (numberParticipants < 1) {
            throw new IllegalArgumentException("Number of participants must be greater than 0");
        }
        if (sharesPerParticipant < 1) {
            throw new IllegalArgumentException("Shares per participant must be greater than 0");
        }
        if (this.numberParticipants != 0 || this.sharesPerParticipant != 0) {
            throw new IllegalStateException("Cannot set committee size when it is already set");
        }
        this.numberParticipants = numberParticipants;
        this.sharesPerParticipant = sharesPerParticipant;

        return this;
    }

    @NonNull
    public CommitteeBuilder withShareDistribution(@NonNull final Pair<Integer, Integer>... distributions) {
        Objects.requireNonNull(distributions, "Distributions cannot be null");
        customShareDistribution = List.of(distributions);
        return this;
    }

    @NonNull
    public CommitteeBuilder withAbsentParticipants(@NonNull final Integer... participants) {
        Objects.requireNonNull(participants, "Participants cannot be null");
        absentParticipants = List.of(participants);
        return this;
    }

    @NonNull
    public CommitteeBuilder withThreshold(final int threshold) {
        if (threshold < 1) {
            throw new IllegalArgumentException("Threshold must be greater than 0");
        }
        customThreshold = threshold;
        return this;
    }

    @NonNull
    TssParticipantDirectory build() {
        if (numberParticipants == 0 || sharesPerParticipant == 0) {
            throw new IllegalStateException("Committee size must be set");
        }
        if (randomKeys) {
            keys = new BlsPrivateKey[numberParticipants];
            final var schema = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS);
            for (int i = 0; i < numberParticipants; i++) {
                keys[i] = BlsPrivateKey.create(schema, beaver.getRng());
            }
        } else if (keys == null) {
            throw new IllegalStateException("Keys must be set");
        }

        final int threshold =
                customThreshold == 0 ? (numberParticipants * sharesPerParticipant + 2) / 2 : customThreshold;

        final var directoryBuilder = TssParticipantDirectory.createBuilder().withThreshold(threshold);

        if (numberParticipants > 0 && sharesPerParticipant > 0) {
            for (int i = 0; i < numberParticipants; i++) {
                if (absentParticipants != null && absentParticipants.contains(i)) {
                    continue;
                }
                directoryBuilder.withParticipant(i, sharesPerParticipant, keys[i].createPublicKey());
            }
        } else if (customShareDistribution != null) {
            for (int i = 0; i < customShareDistribution.size(); i++) {
                if (absentParticipants != null && absentParticipants.contains(i)) {
                    continue;
                }
                final var distribution = customShareDistribution.get(i);
                directoryBuilder.withParticipant(distribution.left(), distribution.right(), keys[i].createPublicKey());
            }
        } else {
            throw new IllegalStateException("Committee size must be set");
        }

        return directoryBuilder.build();
    }

    public Beaver and() {
        beaver.setCommitteeBuilder(this);
        return beaver;
    }

    @NonNull
    BlsPrivateKey[] getKeys() {
        return keys;
    }
}
