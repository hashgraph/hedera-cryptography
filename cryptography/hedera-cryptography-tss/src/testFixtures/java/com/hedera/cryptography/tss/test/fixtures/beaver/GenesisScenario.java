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
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssParticipantPrivateInfo;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssShareExtractor;
import com.hedera.cryptography.tss.extensions.serialization.DefaultTssMessageSerialization;
import com.hedera.cryptography.utils.test.fixtures.QuadConsumer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * A test scenario builder for TSS genesis operations. This class facilitates testing of TSS share generation,
 * extraction, and verification in a controlled environment.
 *
 * <p>The scenario allows for:
 * <ul>
 *   <li>Setting up multiple sender participants</li>
 *   <li>Generating and verifying TSS messages</li>
 *   <li>Extracting and comparing private shares</li>
 *   <li>Verifying ledger ID consistency</li>
 * </ul>
 */
public class GenesisScenario {
    private final Beaver beaver;
    private List<Integer> senders;
    private Map<Integer, byte[]> ledgerIds = new HashMap<>();
    private Map<Integer, TssParticipantPrivateInfo> privateSharesMap = new HashMap<>();
    private List<TssPublicShare> allPublicShares;
    private BlsPublicKey aggregatedPublicKey;
    private List<TssMessage> messages;

    /**
     * Creates a new genesis scenario with the specified Beaver instance.
     *
     * @param beaver The Beaver instance containing committee and service configurations
     * @throws NullPointerException  if beaver is null
     * @throws IllegalStateException if committee or TSS service is not configured in the beaver instance
     */
    public GenesisScenario(@NonNull Beaver beaver) {
        this.beaver = Objects.requireNonNull(beaver, "beaver must not be null");
        if (beaver.getCommittee() == null) {
            throw new IllegalStateException("Committee must be set before genesis scenario can be created");
        }
        if (beaver.getTssService() == null) {
            throw new IllegalStateException("TssService must be set before genesis scenario can be created");
        }
    }

    /**
     * Specifies the participant IDs that will act as senders in this scenario.
     *
     * @param senders Array of participant IDs
     * @return This scenario instance for method chaining
     * @throws NullPointerException     if senders array is null
     * @throws IllegalArgumentException if senders array is empty
     */
    @NonNull
    public GenesisScenario senders(@NonNull final int... senders) {
        Objects.requireNonNull(senders, "senders cannot be null");
        if (senders.length == 0) {
            throw new IllegalArgumentException("senders cannot be empty");
        }
        this.senders = Arrays.stream(senders).boxed().collect(Collectors.toList());
        return this;
    }

    /**
     * Executes the genesis test scenario by generating TSS messages, extracting shares, and preparing verification
     * data.
     *
     * @return This scenario instance for method chaining
     * @throws NullPointerException  if any required components are null
     * @throws IllegalStateException if senders have not been set or if the number of shares doesn't match
     * @throws Exception             if any other error occurs during test execution
     */
    @NonNull
    public GenesisScenario test() throws Exception {
        final TssParticipantDirectory committee = beaver.getCommittee();
        final var committeeBuilder = beaver.getCommitteeBuilder();
        final TssService tssService = beaver.getTssService();

        if (senders == null) {
            throw new IllegalStateException("senders must be set");
        }

        messages =
                IntStream.range(0, committeeBuilder.getNumberParticipants()).mapToObj(i -> {
                            if (!senders.contains(i)) {
                                return null;
                            }
                            final var myMessage = tssService.genesisStage().generateTssMessage(committee);
                            Objects.requireNonNull(myMessage, "message could not be generated");
                            final var serializer = DefaultTssMessageSerialization.getSerializer(committeeBuilder.getSchema());
                            assertNotNull(
                                    DefaultTssMessageSerialization.getDeserializer(committeeBuilder.getSchema(), committee)
                                            .deserialize(serializer.serialize(myMessage)));
                            return myMessage;
                        })
                        .filter(Objects::nonNull)
                        .toList();

        final var tssShareExtractor = tssService.genesisStage().shareExtractor(committee, messages);

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


    /**
     * Verifies that the ledger IDs are equal for the specified participants.
     *
     * @param participantIds Array of participant IDs to compare
     * @return This scenario instance for method chaining
     * @throws IllegalArgumentException if fewer than two participant IDs are provided
     * @throws AssertionError           if the ledger IDs are not equal
     */
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

    /**
     * Retrieves and verifies private share information for a single participant.
     *
     * @param participantId The ID of the participant whose share should be verified
     * @param assertion     A consumer that performs the verification
     * @return This scenario instance for method chaining
     * @throws NullPointerException if assertion is null or if required components are missing
     */
    @NonNull
    public GenesisScenario retrievePrivateShare(int participantId,
            QuadConsumer<TssShareExtractor, TssParticipantDirectory, List<TssPublicShare>, TssParticipantPrivateInfo> assertion) {
        assertion.accept(beaver.getTssService().genesisStage().shareExtractor(beaver.getCommittee(), messages),
                beaver.getCommittee(), allPublicShares,
                privateSharesMap.get(participantId));
        return this;
    }
}
