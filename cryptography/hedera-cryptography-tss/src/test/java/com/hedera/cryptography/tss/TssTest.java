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
import static org.mockito.Mockito.when;

import com.hedera.common.testfixtures.WithRng;
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
import com.hedera.cryptography.tss.api.TssShareId;
import com.hedera.cryptography.tss.api.TssShareSignature;
import com.hedera.cryptography.tss.impl.TssServiceTestImpl;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * A test to showcase the Tss protocol for a specific case
 * More validations can be added once
 */
@WithRng
class TssTest {

    public static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);

    @Test
    void testGenesis(final Random rng) {
        // Simulates the genesis process for a 3 participant network
        final BlsPublicKey publicKey1 = mock(BlsPublicKey.class);
        final BlsPublicKey publicKey2 = mock(BlsPublicKey.class);
        final BlsPublicKey publicKey3 = mock(BlsPublicKey.class);

        final TssParticipantDirectory p0sDirectory = TssParticipantDirectory.createBuilder()
                .withSelf(0, Mockito.mock(BlsPrivateKey.class))
                .withParticipant(0, 1, publicKey1)
                .withParticipant(1, 1, publicKey2)
                .withParticipant(2, 1, publicKey3)
                .withThreshold(2)
                .build(SIGNATURE_SCHEMA);

        final TssService tssService = new TssServiceTestImpl(SIGNATURE_SCHEMA, rng);

        // this message will contain a random share split in 3 parts
        final TssMessage p0Message = tssService.generateTssMessage(p0sDirectory);

        final TssParticipantDirectory p1sDirectory = TssParticipantDirectory.createBuilder()
                .withSelf(1, mock(BlsPrivateKey.class))
                .withParticipant(0, 1, publicKey1)
                .withParticipant(1, 1, publicKey2)
                .withParticipant(2, 1, publicKey3)
                .withThreshold(2)
                .build(SIGNATURE_SCHEMA);

        // this message will contain a random share split in 3 parts
        final TssMessage p1Message = tssService.generateTssMessage(p1sDirectory);

        final TssParticipantDirectory p2sDirectory = TssParticipantDirectory.createBuilder()
                .withSelf(2, mock(BlsPrivateKey.class))
                .withParticipant(0, 1, publicKey1)
                .withParticipant(1, 1, publicKey2)
                .withParticipant(2, 1, publicKey3)
                .withThreshold(2)
                .build(SIGNATURE_SCHEMA);

        // this message will contain a random share split in 3 parts
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
        Objects.requireNonNull(
                tssService.decryptPrivateShares(p0sDirectory, validMessages),
                "Condition of threshold number of messages was not met");

        // Get the list of PublicShares
        final List<TssPublicShare> publicShares = Objects.requireNonNull(
                tssService.computePublicShares(p0sDirectory, validMessages),
                "Condition of threshold number of messages was not met");

        // Get the ledgerId
        tssService.aggregatePublicShares(publicShares);
    }

    @Test
    void testSigning(final Random random) {
        // given:
        // all this will be calculated at genesis
        final BlsPublicKey publicKey1 = mock(BlsPublicKey.class);
        final BlsPublicKey publicKey2 = mock(BlsPublicKey.class);
        final BlsPublicKey publicKey3 = mock(BlsPublicKey.class);

        final TssParticipantDirectory p0sDirectory = TssParticipantDirectory.createBuilder()
                .withSelf(0, mock(BlsPrivateKey.class))
                .withParticipant(0, 1, publicKey1)
                .withParticipant(1, 1, publicKey2)
                .withParticipant(2, 1, publicKey3)
                .withThreshold(2)
                .build(SIGNATURE_SCHEMA);

        final TssService tssService = new TssServiceTestImpl(SIGNATURE_SCHEMA, new Random(random.nextLong()));
        final BlsPrivateKey s = BlsPrivateKey.create(SIGNATURE_SCHEMA, new Random(random.nextLong()));
        TssPublicShare mockPublic = mock(TssPublicShare.class);
        when(mockPublic.publicKey()).thenReturn(s.createPublicKey());
        final List<TssPublicShare> publicShares =
                List.of(mock(TssPublicShare.class), mock(TssPublicShare.class), mock(TssPublicShare.class));
        final BlsPublicKey ledgerID = tssService.aggregatePublicShares(publicShares);
        TssPrivateShare mock = mock(TssPrivateShare.class);
        when(mock.shareId()).thenReturn(mock(TssShareId.class));
        when(mock.privateKey()).thenReturn(s);
        final List<TssPrivateShare> privateShares = List.of(mock);

        final byte[] messageToSign = new byte[20];
        random.nextBytes(messageToSign);

        // then
        // After genesis, and assuming the same participantDirectory p0 will have a list of 1 private share

        final List<TssShareSignature> signatures = new ArrayList<>();
        for (TssPrivateShare privateShare : privateShares) {
            signatures.add(tssService.sign(privateShare, messageToSign));
        }

        // After signing, it will collect all other participant signatures
        final List<TssShareSignature> p1Signatures = List.of(mock(TssShareSignature.class));
        final List<TssShareSignature> p2Signatures = List.of(mock(TssShareSignature.class));

        final List<TssShareSignature> collectedSignatures = new ArrayList<>();
        collectedSignatures.addAll(signatures);
        collectedSignatures.addAll(p1Signatures);
        collectedSignatures.addAll(p2Signatures);

        final List<TssShareSignature> validSignatures = collectedSignatures.stream()
                .filter(sign -> tssService.verifySignature(p0sDirectory, publicShares, sign))
                .toList();

        final BlsSignature signature = tssService.aggregateSignatures(validSignatures);

        if (!signature.verify(ledgerID, messageToSign)) {
            throw new IllegalStateException("Signature verification failed");
        }
    }

    @Test
    void rekeying(final Random random) {
        // given:
        // all this will be calculated at genesis
        final BlsPublicKey publicKey1 = mock(BlsPublicKey.class);
        final BlsPublicKey publicKey2 = mock(BlsPublicKey.class);
        final BlsPublicKey publicKey3 = mock(BlsPublicKey.class);

        final TssParticipantDirectory p0sDirectory = TssParticipantDirectory.createBuilder()
                .withSelf(0, mock(BlsPrivateKey.class))
                .withParticipant(0, 1, publicKey1)
                .withParticipant(1, 1, publicKey2)
                .withParticipant(2, 1, publicKey3)
                .withThreshold(2)
                .build(SIGNATURE_SCHEMA);

        final TssService tssService = new TssServiceTestImpl(SIGNATURE_SCHEMA, random);
        final List<TssPublicShare> publicShares =
                List.of(mock(TssPublicShare.class), mock(TssPublicShare.class), mock(TssPublicShare.class));
        final BlsPublicKey ledgerID = tssService.aggregatePublicShares(publicShares);
        final List<TssPrivateShare> oldP0PrivateShares = List.of(mock(TssPrivateShare.class));

        // then:
        final List<TssMessage> p0Messages = new ArrayList<>();
        for (TssPrivateShare privateShare : oldP0PrivateShares) {
            p0Messages.add(tssService.generateTssMessage(p0sDirectory, privateShare));
        }
        // Collect other participants messages
        final List<TssMessage> p1Messages = List.of(mock(TssMessage.class));
        final List<TssMessage> p2Messages = List.of(mock(TssMessage.class));

        final List<TssMessage> collectedValidMessages = Stream.of(p0Messages, p1Messages, p2Messages)
                .flatMap(Collection::stream)
                .filter(tssMessage -> tssService.verifyTssMessage(p0sDirectory, tssMessage))
                .toList();

        // Get the list of PrivateShares owned by participant 0
        Objects.requireNonNull(
                tssService.decryptPrivateShares(p0sDirectory, collectedValidMessages),
                "Condition of threshold number of messages was not met");

        // Get the list of PublicShares
        final List<TssPublicShare> newPublicShares = Objects.requireNonNull(
                tssService.computePublicShares(p0sDirectory, collectedValidMessages),
                "Condition of threshold number of messages was not met");

        // calculate the ledgerId out of the newly calculated publicShares
        final BlsPublicKey ledgerId = tssService.aggregatePublicShares(newPublicShares);

        if (!ledgerId.equals(ledgerID)) {
            throw new IllegalStateException("LedgerId must remain constant throughout the rekeying process");
        }
    }
}
