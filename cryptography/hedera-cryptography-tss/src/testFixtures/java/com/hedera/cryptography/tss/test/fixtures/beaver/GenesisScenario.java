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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssParticipantPrivateInfo;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssShareExtractor;
import com.hedera.cryptography.tss.extensions.serialization.DefaultTssMessageSerialization;
import com.hedera.cryptography.utils.test.fixtures.HexaConsumer;
import com.hedera.cryptography.utils.test.fixtures.QuadConsumer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class GenesisScenario {
    private final Beaver beaver;
    private List<Integer> senders;
    private Map<Integer, byte[]> ledgerIds = new HashMap<>();
    private Map<Integer, TssParticipantPrivateInfo> privateSharesMap = new HashMap<>();
    private List<TssPublicShare> allPublicShares;
    private BlsPublicKey aggregatedPublicKey;
    private TssShareExtractor tssShareExtractor;

    public GenesisScenario(@NonNull Beaver beaver) {
        this.beaver = Objects.requireNonNull(beaver, "beaver must not be null");
        if (beaver.getCommittee() == null) {
            throw new IllegalStateException("Committee must be set before genesis scenario can be created");
        }
        if (beaver.getTssService() == null) {
            throw new IllegalStateException("TssService must be set before genesis scenario can be created");
        }
    }

    @NonNull
    public GenesisScenario senders(@NonNull final int... senders) {
        Objects.requireNonNull(senders, "senders cannot be null");
        if (senders.length == 0) {
            throw new IllegalArgumentException("senders cannot be empty");
        }
        this.senders = Arrays.stream(senders).boxed().collect(Collectors.toList());
        return this;
    }

    @NonNull
    public GenesisScenario test() throws Exception {
        final TssParticipantDirectory committee = beaver.getCommittee();
        final var committeeBuilder = beaver.getCommitteeBuilder();
        final TssService tssService = beaver.getTssService();

        if (senders == null) {
            throw new IllegalStateException("senders must be set");
        }

        final var myMessage = tssService.genesisStage().generateTssMessage(committee);
        Objects.requireNonNull(myMessage, "message could not be generated");
        final var serializer = DefaultTssMessageSerialization.getSerializer(committeeBuilder.getSchema());
        assertNotNull(DefaultTssMessageSerialization.getDeserializer(committeeBuilder.getSchema(), committee)
                .deserialize(serializer.serialize(myMessage)));
        final var otherMessage = tssService.genesisStage().generateTssMessage(committee);
        tssShareExtractor =
                tssService.genesisStage().shareExtractor(committee, List.of(myMessage, otherMessage));

        allPublicShares = tssShareExtractor.allPublicShares();
        Objects.requireNonNull(allPublicShares, "public shares could not be extracted");

        if (!Objects.equals(committeeBuilder.getNumberOfShares(), allPublicShares.size())) {
            throw new IllegalStateException("Number of shares does not match");
        }

        aggregatedPublicKey = TssPublicShare.aggregate(allPublicShares);
        assertNotNull(aggregatedPublicKey);

        for (int i = 0; i < committeeBuilder.getNumberParticipants(); i++) {
            privateSharesMap.put(i, committeeBuilder.privateInfoOf(i));
        }

        return this;
    }

    @NonNull
    public GenesisScenario assertEqualLedgerIds(int... participantIds) {
        if (participantIds.length < 2) {
            throw new IllegalArgumentException("At least two participant IDs are required for comparison");
        }

        byte[] firstLedgerId = ledgerIds.get(participantIds[0]);
        for (int i = 1; i < participantIds.length; i++) {
            if (!Arrays.equals(firstLedgerId, ledgerIds.get(participantIds[i]))) {
                throw new AssertionError(
                        "Ledger IDs are not equal for participants " + participantIds[0] + " and " + participantIds[i]);
            }
        }
        return this;
    }

    @NonNull
    public GenesisScenario retrievePrivateShare(int participantId,
            QuadConsumer<TssShareExtractor, TssParticipantDirectory, List<TssPublicShare>, TssParticipantPrivateInfo> assertion) {
        assertion.accept(tssShareExtractor, beaver.getCommittee(), allPublicShares,
                privateSharesMap.get(participantId));
        return this;
    }

    @NonNull
    public GenesisScenario retrievePrivateShares(int participantId1, int participantId2,
            HexaConsumer<TssShareExtractor, TssParticipantDirectory, List<TssPublicShare>, BlsPublicKey, TssParticipantPrivateInfo, TssParticipantPrivateInfo> assertion) {
        assertion.accept(tssShareExtractor, beaver.getCommittee(), allPublicShares, aggregatedPublicKey,
                privateSharesMap.get(participantId1),
                privateSharesMap.get(participantId2));
        return this;
    }


}
