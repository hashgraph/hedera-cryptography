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

import static com.hedera.cryptography.tss.test.fixtures.TssTestUtils.rndSks;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssShareExtractor;
import com.hedera.cryptography.tss.api.TssShareSignature;
import com.hedera.cryptography.tss.test.fixtures.TestTssServiceImpl;
import com.hedera.cryptography.tss.test.fixtures.TssTestCommittee;
import com.hedera.cryptography.tss.test.fixtures.TssTestUtils;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import com.hedera.cryptography.utils.test.fixtures.stream.StreamUtils;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A test to showcase the Tss protocol for a specific use-case
 */
@WithRng
class TssTest {

    public static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);
    public static final int GENESIS_SIZE = 2;
    public static final int GENESIS_SHARES = 5;
    public static final int TARGET_SIZE = 4;
    public static final int TARGET_SHARES = 5;

    private BlsPrivateKey[] keys;
    private TssService tssService;

    @BeforeEach
    void setup(Random rng) {
        keys = rndSks(SIGNATURE_SCHEMA, rng, Math.max(GENESIS_SIZE, TARGET_SIZE));
        tssService = new TestTssServiceImpl(SIGNATURE_SCHEMA);
    }

    @Test
    void testGenesis() {
        var genesisCommittee = new TssTestCommittee(GENESIS_SIZE, GENESIS_SHARES, keys);
        var participantDirectory = genesisCommittee.participantDirectory();
        var myMessage = tssService.genesisStage().generateTssMessage(participantDirectory);
        var myInfo = genesisCommittee.privateInfoOf(0);
        assertNotNull(myMessage);
        assertNotNull(tssService.messageFromBytes(myMessage.bytes()));
        var otherMessage = tssService.genesisStage().generateTssMessage(participantDirectory);
        final TssShareExtractor tssShareExtractor =
                tssService.genesisStage().shareExtractor(participantDirectory, List.of(myMessage, otherMessage));

        final var allPublicShares = tssShareExtractor.allPublicShares();
        assertNotNull(allPublicShares);
        assertEquals(GENESIS_SIZE * GENESIS_SHARES, allPublicShares.size());

        final BlsPublicKey aggregatedPublicKey = TssPublicShare.aggregate(allPublicShares);
        assertNotNull(aggregatedPublicKey);

        final var privateShares = tssShareExtractor.ownedPrivateShares(myInfo);
        assertNotNull(privateShares);
        assertEquals(GENESIS_SHARES, privateShares.size());

        var ownedPublicShares = myInfo.ownedShares(participantDirectory).stream()
                .map(share -> allPublicShares.get(share - 1))
                .toList();
        StreamUtils.zipStream(privateShares, ownedPublicShares)
                .forEach(e -> assertEquals(
                        e.getKey().privateKey().createPublicKey(), e.getValue().publicKey()));

        var otherInfo = genesisCommittee.privateInfoOf(1);
        final var otherPrivateShares = tssService
                .genesisStage()
                .shareExtractor(participantDirectory, List.of(myMessage, otherMessage))
                .ownedPrivateShares(otherInfo);
        assertNotNull(otherPrivateShares);

        var allPrivateShares = new ArrayList<>(privateShares);
        allPrivateShares.addAll(otherPrivateShares);
        var signatures = allPrivateShares.stream()
                .map(share -> share.sign("MyMessage".getBytes()))
                .toList();
        var aggregatedSignature = TssShareSignature.aggregate(signatures);

        assertTrue(aggregatedSignature.verify(aggregatedPublicKey, "MyMessage".getBytes()));
    }

    @Test
    void testRekey(Random random) {
        var self = 0;
        var genesisCommittee = new TssTestCommittee(GENESIS_SIZE, GENESIS_SHARES, keys);

        var genesisMessages = TssTestUtils.simulateGenesisMessaging(tssService, genesisCommittee);
        final TssShareExtractor genesisShareExtractor = tssService
                .genesisStage()
                .shareExtractor(genesisCommittee.participantDirectory(), genesisMessages)
                .extract(genesisCommittee.privateInfoOf(self));

        var pastPublicShares = genesisShareExtractor.allPublicShares();
        var pastLedgerId = TssPublicShare.aggregate(pastPublicShares);
        var allPrivateShares = genesisCommittee.allPrivateInfo().stream()
                .map(privateInfo -> tssService
                        .genesisStage()
                        .shareExtractor(genesisCommittee.participantDirectory(), genesisMessages)
                        .ownedPrivateShares(privateInfo))
                .toList();

        // *************** Rekey process
        var targetCommittee = new TssTestCommittee(TARGET_SIZE, TARGET_SHARES, keys);
        var rekeyMessages = TssTestUtils.simulateRekeyMessaging(tssService, targetCommittee, allPrivateShares);

        for (var message : rekeyMessages) {
            assertTrue(tssService
                    .rekeyStage()
                    .verifyTssMessage(targetCommittee.participantDirectory(), pastPublicShares, message));
        }

        final TssShareExtractor tssShareExtractor =
                tssService.rekeyStage().shareExtractor(targetCommittee.participantDirectory(), rekeyMessages);

        var selectedParticipantPrivateInfo = targetCommittee.privateInfoOf(self);
        tssShareExtractor.extract(selectedParticipantPrivateInfo);
        var privateShares = tssShareExtractor.ownedPrivateShares(selectedParticipantPrivateInfo);
        var publicShares = tssShareExtractor.allPublicShares();
        assertNotNull(privateShares);
        assertNotNull(publicShares);
        var ownedPublicShares =
                selectedParticipantPrivateInfo.ownedShares(targetCommittee.participantDirectory()).stream()
                        .map(share -> publicShares.get(share - 1))
                        .toList();

        StreamUtils.zipStream(privateShares, ownedPublicShares)
                .forEach(e -> assertEquals(
                        e.getKey().privateKey().createPublicKey(), e.getValue().publicKey()));
        var rekeyedLedgerId = TssPublicShare.aggregate(publicShares);
        assertEquals(pastLedgerId, rekeyedLedgerId);
    }
}
