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

package com.hedera.cryptography.tss;

import static org.mockito.Mockito.mock;

import com.hedera.cryptography.bls.BlsKeyPair;
import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.BlsSignature;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssShareSignature;
import com.hedera.cryptography.tss.impl.TssServiceTestImpl;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * A test to showcase the Tss protocol for a specific case
 * More validations can be added once
 */
class TssTest {

    public static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);
    public static final Random rng = new Random(600);

    @Test
    void testGenesis() {
        // Simulates the genesis process for a 3 participant network
        final BlsKeyPair keyPair1 = BlsKeyPair.generate(SIGNATURE_SCHEMA, rng);
        final BlsKeyPair keyPair2 = BlsKeyPair.generate(SIGNATURE_SCHEMA, rng);
        final BlsKeyPair keyPair3 = BlsKeyPair.generate(SIGNATURE_SCHEMA, rng);

        final TssParticipantDirectory p0sDirectory = TssParticipantDirectory.createBuilder()
                .withSelf(0, keyPair1.privateKey())
                .withParticipant(0, 1, keyPair1.publicKey())
                .withParticipant(1, 1, keyPair2.publicKey())
                .withParticipant(2, 1, keyPair3.publicKey())
                .withThreshold(2)
                .build(SIGNATURE_SCHEMA);

        final TssService tssService = new TssServiceTestImpl(SIGNATURE_SCHEMA, new Random());

        // this message will contain a sharedRandomness share split in 3 parts
        final TssMessage p0Message = tssService.generateTssMessage(p0sDirectory);

        final TssParticipantDirectory p1sDirectory = TssParticipantDirectory.createBuilder()
                .withSelf(1, keyPair2.privateKey())
                .withParticipant(0, 1, keyPair1.publicKey())
                .withParticipant(1, 1, keyPair2.publicKey())
                .withParticipant(2, 1, keyPair3.publicKey())
                .withThreshold(2)
                .build(SIGNATURE_SCHEMA);

        // this message will contain a sharedRandomness share split in 3 parts
        final TssMessage p1Message = tssService.generateTssMessage(p1sDirectory);

        final TssParticipantDirectory p2sDirectory = TssParticipantDirectory.createBuilder()
                .withSelf(2, keyPair3.privateKey())
                .withParticipant(0, 1, keyPair1.publicKey())
                .withParticipant(1, 1, keyPair2.publicKey())
                .withParticipant(2, 1, keyPair3.publicKey())
                .withThreshold(2)
                .build(SIGNATURE_SCHEMA);

        // this message will contain a sharedRandomness share split in 3 parts
        final TssMessage p2Message = tssService.generateTssMessage(p2sDirectory);

        // Some other piece will distribute messages across all participants

        // And simulating processing in P0
        final List<TssMessage> messages = List.of(p0Message, p1Message, p2Message);
        final List<TssMessage> validMessages = messages.stream()
                .filter(tssMessage -> tssService.verifyTssMessage(p0sDirectory, tssMessage))
                .toList();

        if (validMessages.size() < p0sDirectory.getThreshold()) {
            throw new IllegalStateException("There should be at least threshold number of valid messages");
        }

        // Get the list of PrivateShares owned by participant 0
        final List<TssPrivateShare> privateShares = Objects.requireNonNull(
                tssService.obtainPrivateShares(p0sDirectory, validMessages),
                "Condition of threshold number of messages was not met");

        // Get the list of PublicShares
        final List<TssPublicShare> publicShares = Objects.requireNonNull(
                tssService.obtainPublicShares(p0sDirectory, validMessages),
                "Condition of threshold number of messages was not met");

        // Get the ledgerId
        final BlsPublicKey ledgerId = TssPublicShare.aggregate(publicShares);
    }

    @Test
    void testSigning() {
        // given:
        // all this will be calculated at genesis
        // Simulates the genesis process for a 3 participant network
        final BlsKeyPair keyPair1 = BlsKeyPair.generate(SIGNATURE_SCHEMA, rng);
        final BlsKeyPair keyPair2 = BlsKeyPair.generate(SIGNATURE_SCHEMA, rng);
        final BlsKeyPair keyPair3 = BlsKeyPair.generate(SIGNATURE_SCHEMA, rng);
        final BlsPublicKey publicKey1 = keyPair1.publicKey();
        final BlsPublicKey publicKey2 = keyPair2.publicKey();
        final BlsPublicKey publicKey3 = keyPair3.publicKey();

        final TssParticipantDirectory p0sDirectory = TssParticipantDirectory.createBuilder()
                .withSelf(0, keyPair1.privateKey())
                .withParticipant(0, 1, publicKey1)
                .withParticipant(1, 1, publicKey2)
                .withParticipant(2, 1, publicKey3)
                .withThreshold(2)
                .build(SIGNATURE_SCHEMA);

        final TssService tssService = new TssServiceTestImpl(SIGNATURE_SCHEMA, new Random());

        final List<TssMessage> tssMessages =
                List.of(mock(TssMessage.class), mock(TssMessage.class), mock(TssMessage.class), mock(TssMessage.class));

        final var validMessages = tssMessages.stream()
                .filter(m -> tssService.verifyTssMessage(p0sDirectory, m))
                .toList();
        final var publicShares = tssService.obtainPublicShares(p0sDirectory, validMessages); // Reduce to threshold?

        final var ledgerID = TssPublicShare.aggregate(publicShares);

        final byte[] messageToSign = new byte[20];
        rng.nextBytes(messageToSign);
        final var privateShares = tssService.obtainPrivateShares(p0sDirectory, validMessages);

        // then
        // After genesis, and assuming the same participantDirectory p0 will have a list of 1 private share

        var signatures = privateShares.stream().map(p -> p.sign(messageToSign)).toList();

        // After signing, it will collect all other participant signatures
        final List<TssShareSignature> p1Signatures = List.of(TssShareSignature.of(
                2,
                new BlsPrivateKey(
                                SIGNATURE_SCHEMA
                                        .getPairingFriendlyCurve()
                                        .field()
                                        .fromLong(2),
                                SIGNATURE_SCHEMA)
                        .sign(messageToSign)));
        final List<TssShareSignature> p2Signatures = List.of(TssShareSignature.of(
                3,
                new BlsPrivateKey(
                                SIGNATURE_SCHEMA
                                        .getPairingFriendlyCurve()
                                        .field()
                                        .fromLong(3),
                                SIGNATURE_SCHEMA)
                        .sign(messageToSign)));

        final List<TssShareSignature> collectedSignatures = new ArrayList<>();
        collectedSignatures.addAll(signatures);
        collectedSignatures.addAll(p1Signatures);
        collectedSignatures.addAll(p2Signatures);

        var publicSharesMap =
                publicShares.stream().collect(Collectors.toMap(TssPublicShare::shareId, Function.identity()));
        final List<TssShareSignature> validSignatures = collectedSignatures.stream()
                .filter(sign -> sign.verify(publicSharesMap.get(sign.shareId()), messageToSign))
                .toList();

        final BlsSignature signature = TssShareSignature.aggregate(validSignatures);

        if (!signature.verify(ledgerID, messageToSign)) {
            throw new IllegalStateException("Signature verification failed");
        }
    }

    @Test
    void rekeying() {
        // given:
        // all this will be calculated at genesis
        final BlsKeyPair keyPair1 = BlsKeyPair.generate(SIGNATURE_SCHEMA, rng);
        final BlsKeyPair keyPair2 = BlsKeyPair.generate(SIGNATURE_SCHEMA, rng);
        final BlsKeyPair keyPair3 = BlsKeyPair.generate(SIGNATURE_SCHEMA, rng);
        final BlsPublicKey publicKey1 = keyPair1.publicKey();
        final BlsPublicKey publicKey2 = keyPair2.publicKey();
        final BlsPublicKey publicKey3 = keyPair3.publicKey();

        final TssParticipantDirectory p0sDirectory = TssParticipantDirectory.createBuilder()
                .withSelf(0, keyPair1.privateKey())
                .withParticipant(0, 1, publicKey1)
                .withParticipant(1, 1, publicKey2)
                .withParticipant(2, 1, publicKey3)
                .withThreshold(2)
                .build(SIGNATURE_SCHEMA);

        final TssService tssService = new TssServiceTestImpl(SIGNATURE_SCHEMA, new Random());
        final List<TssMessage> tssMessages =
                List.of(mock(TssMessage.class), mock(TssMessage.class), mock(TssMessage.class), mock(TssMessage.class));

        final var validMessages = tssMessages.stream()
                .filter(m -> tssService.verifyTssMessage(p0sDirectory, m))
                .toList();
        final var oldPublicShares = tssService.obtainPublicShares(p0sDirectory, validMessages); // Reduce to threshold?
        final var oldP0PrivateShares =
                tssService.obtainPrivateShares(p0sDirectory, validMessages); // Reduce to threshold?

        final var ledgerID = TssPublicShare.aggregate(oldPublicShares);
        // then:
        final List<TssMessage> p0Messages = oldP0PrivateShares.stream()
                .map(p -> tssService.generateTssMessage(p0sDirectory, p))
                .toList();

        // Collect other participants messages
        final List<TssMessage> p1Messages = List.of(mock(TssMessage.class));
        final List<TssMessage> p2Messages = List.of(mock(TssMessage.class));

        final List<TssMessage> collectedValidMessages = Stream.of(p0Messages, p1Messages, p2Messages)
                .flatMap(Collection::stream)
                .filter(tssMessage -> tssService.verifyTssMessage(p0sDirectory, oldPublicShares, tssMessage))
                .toList();

        // Get the list of PrivateShares owned by participant 0
        final List<TssPrivateShare> newP0privateShares = Objects.requireNonNull(
                tssService.obtainPrivateShares(p0sDirectory, collectedValidMessages),
                "Condition of threshold number of messages was not met");

        // Get the list of PublicShares
        final List<TssPublicShare> newPublicShares = Objects.requireNonNull(
                tssService.obtainPublicShares(p0sDirectory, collectedValidMessages),
                "Condition of threshold number of messages was not met");

        // calculate the ledgerId out of the newly calculated newPublicShares
        final BlsPublicKey ledgerId = TssPublicShare.aggregate(newPublicShares);

        if (!ledgerId.equals(ledgerID)) {
            throw new IllegalStateException("LedgerId must remain constant throughout the rekeying process");
        }
    }
}
