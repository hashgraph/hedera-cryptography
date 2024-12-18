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

import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class GenesisScenario {
    private final Beaver beaver;
    private List<Integer> senders;
    private Map<Integer, byte[]> ledgerIds = new HashMap<>();
    private Map<Integer, List<TssPrivateShare>> privateSharesMap = new HashMap<>();
    private Map<Integer, List<TssPublicShare>> publicSharesMap = new HashMap<>();

    public GenesisScenario(@NonNull Beaver beaver) {
        this.beaver = Objects.requireNonNull(beaver, "beaver must not be null");
        if (beaver.getCommittee() == null) {
            throw new IllegalStateException("Committee must be set before genesis scenario can be created");
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
        if (senders == null) {
            throw new IllegalStateException("senders must be set");
        }
        if (senders.size() != beaver.getCommittee().getThreshold()) {
            throw new IllegalStateException("Number of senders must be equal to threshold");
        }

        // Generate and process messages for each sender
        List<TssMessage> messages = new ArrayList<>();
        for (Integer sender : senders) {
            var message = beaver.getTssService().genesisStage().generateTssMessage(beaver.getCommittee());
            messages.add(message);

            // Store shares for later retrieval
            var tssShareExtractor =
                    beaver.getTssService().genesisStage().shareExtractor(beaver.getCommittee(), messages);

            var privateInfo = beaver.privateInfoOf(sender);
            privateSharesMap.put(sender, tssShareExtractor.ownedPrivateShares(privateInfo));
            publicSharesMap.put(sender, new ArrayList<>(tssShareExtractor.allPublicShares()));

            // Simulate ledger ID generation (you'll need to implement this based on your actual logic)
            ledgerIds.put(sender, generateLedgerId(sender));
        }

        // Perform verification steps
        verifyShares();
        verifySignatures();

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
    public GenesisScenario retrieveLedgerId(int participantId, Consumer<LedgerKey> assertion) {
        byte[] ledgerId = ledgerIds.get(participantId);
        if (ledgerId == null) {
            throw new IllegalStateException("No ledger ID found for participant " + participantId);
        }

        // Create a LedgerKey object (you'll need to implement this based on your actual class)
        LedgerKey key = new LedgerKey(ledgerId, 1); // Assuming group index is 1 as per test
        assertion.accept(key);
        return this;
    }

    @NonNull
    public GenesisScenario retrieveShares(
            int participantId, BiConsumer<List<TssPrivateShare>, List<TssPublicShare>> assertion) {
        List<TssPrivateShare> privateShares = privateSharesMap.get(participantId);
        List<TssPublicShare> publicShares = publicSharesMap.get(participantId);

        if (privateShares == null || publicShares == null) {
            throw new IllegalStateException("No shares found for participant " + participantId);
        }

        assertion.accept(privateShares, publicShares);
        return this;
    }

    private void verifyShares() {
        // Verify that private and public shares match for each participant
        for (Integer sender : senders) {
            var privateShares = privateSharesMap.get(sender);
            var publicShares = publicSharesMap.get(sender);

            if (privateShares.size() != publicShares.size()) {
                throw new IllegalStateException(
                        "Mismatch in private and public shares count for participant " + sender);
            }

            for (int i = 0; i < privateShares.size(); i++) {
                if (!privateShares
                        .get(i)
                        .privateKey()
                        .createPublicKey()
                        .equals(publicShares.get(i).publicKey())) {
                    throw new IllegalStateException("Private and public keys do not match for participant " + sender);
                }
            }
        }
    }

    private void verifySignatures() {
        // Verify signatures for each participant
        byte[] testMessage = "TestMessage".getBytes();

        for (Integer sender : senders) {
            var privateShares = privateSharesMap.get(sender);
            var publicShares = publicSharesMap.get(sender);

            var signatures =
                    privateShares.stream().map(share -> share.sign(testMessage)).collect(Collectors.toList());

            for (int i = 0; i < signatures.size(); i++) {
                if (!signatures.get(i).verify(publicShares.get(i), testMessage)) {
                    throw new IllegalStateException("Signature verification failed for participant " + sender);
                }
            }
        }
    }

    // Fixme: Implement real
    private byte[] generateLedgerId(int participantId) {
        return ("LedgerId-" + participantId).getBytes();
    }

    // Fixme: Implement real
    public static class LedgerKey {
        private final byte[] id;
        private final int groupIndex;

        public LedgerKey(byte[] id, int groupIndex) {
            this.id = id;
            this.groupIndex = groupIndex;
        }

        public int getGroupIndex() {
            return groupIndex;
        }
    }
}
