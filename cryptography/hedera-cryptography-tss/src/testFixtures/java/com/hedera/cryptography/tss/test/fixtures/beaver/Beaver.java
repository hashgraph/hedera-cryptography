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
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssParticipantPrivateInfo;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.utils.test.fixtures.rng.SeededRandom;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.ExecutorService;

public class Beaver {
    private final Random rng;
    private CommitteeBuilder committeeBuilder;
    private TssService tssService;
    private SignatureSchema signatureSchema;
    private ExecutorService executorService;
    private TssParticipantDirectory committee;
    private BlsPrivateKey[] privateKeys;

    public Beaver() {
        this(new SeededRandom());
    }

    public Beaver(final SeededRandom random) {
        this.rng = random;
    }

    @NonNull
    Random getRng() {
        return rng;
    }

    public CommitteeBuilder withCommittee() {
        return new CommitteeBuilder(this);
    }

    void setCommitteeBuilder(@NonNull final CommitteeBuilder committeeBuilder) {
        this.committeeBuilder = Objects.requireNonNull(committeeBuilder, "committeeBuilder cannot be null");
        privateKeys = committeeBuilder.getKeys();
        committee = Objects.requireNonNull(committeeBuilder.build(), "committee cannot be created");
    }

    @NonNull
    TssParticipantDirectory getCommittee() {
        return committee;
    }

    @NonNull
    BlsPrivateKey[] getKeys() {
        return privateKeys;
    }

    @NonNull
    TssParticipantPrivateInfo privateInfoOf(final int participantId) {
        return new TssParticipantPrivateInfo(participantId, privateKeys[participantId]);
    }

    public Beaver withTssService(@NonNull final TssService tssService) {
        this.tssService = Objects.requireNonNull(tssService, "tssService cannot be null");
        return this;
    }

    @NonNull
    TssService getTssService() {
        return tssService;
    }

    public GenesisScenario genesis() {
        return new GenesisScenario(this);
    }
}
