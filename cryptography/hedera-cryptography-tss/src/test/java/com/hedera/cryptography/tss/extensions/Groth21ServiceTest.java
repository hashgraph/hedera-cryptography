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

package com.hedera.cryptography.tss.extensions;

import static com.hedera.cryptography.tss.test.fixtures.TssTestUtils.rndSks;
import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.tss.api.TssMessageParsingException;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssShareSignature;
import com.hedera.cryptography.tss.extensions.serialization.DefaultTssMessageSerialization;
import com.hedera.cryptography.tss.test.fixtures.TssTestCommittee;
import com.hedera.cryptography.tss.test.fixtures.TssTestUtils;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import com.hedera.cryptography.utils.test.fixtures.stream.StreamUtils;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@WithRng
class Groth21ServiceTest {
    static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);

    static final TssService SERVICE = new Groth21Service(SIGNATURE_SCHEMA, new Random());
    public static final int GENESIS_SIZE = 2;
    public static final int GENESIS_SHARES = 5;
    public static final int TARGET_SIZE = 4;
    public static final int TARGET_SHARES = 5;

    private BlsPrivateKey[] keys;
    private TssService tssService;

    @BeforeEach
    void setup(Random rng) {
        keys = rndSks(SIGNATURE_SCHEMA, rng, Math.max(GENESIS_SIZE, TARGET_SIZE));
        tssService = new Groth21Service(SIGNATURE_SCHEMA, rng);
    }

    @Test
    void testGenesisStageNonNull() {
        assertNotNull(SERVICE.genesisStage());
    }

    @Test
    void testRekeyStageNonNull() {
        assertNotNull(SERVICE.rekeyStage());
    }

    @Test
    void testToBytesAndBackAgain() throws TssMessageParsingException {
        var genesisCommittee = new TssTestCommittee(1, 2, keys);
        var participantDirectory = genesisCommittee.participantDirectory();
        var myMessage = tssService.genesisStage().generateTssMessage(participantDirectory);
        var serializer = DefaultTssMessageSerialization.getSerializer(SIGNATURE_SCHEMA);
        var myMessageBytes = serializer.serialize(myMessage);

        var message = DefaultTssMessageSerialization.getDeserializer(SIGNATURE_SCHEMA, participantDirectory)
                .deserialize(myMessageBytes);

        assertArrayEquals(myMessageBytes, serializer.serialize(message));
        assertTrue(tssService.genesisStage().verifyTssMessage(participantDirectory, message));
    }

    @Test
    void testGenesis() throws TssMessageParsingException {
        final var genesisCommittee = new TssTestCommittee(GENESIS_SIZE, GENESIS_SHARES, keys);
        final var participantDirectory = genesisCommittee.participantDirectory();
        final var myMessage = tssService.genesisStage().generateTssMessage(participantDirectory);
        final var myInfo = genesisCommittee.privateInfoOf(0);
        assertNotNull(myMessage);
        var serializer = DefaultTssMessageSerialization.getSerializer(SIGNATURE_SCHEMA);
        assertNotNull(DefaultTssMessageSerialization.getDeserializer(SIGNATURE_SCHEMA, participantDirectory)
                .deserialize(serializer.serialize(myMessage)));
        final var otherMessage = tssService.genesisStage().generateTssMessage(participantDirectory);
        final var tssShareExtractor =
                tssService.genesisStage().shareExtractor(participantDirectory, List.of(myMessage, otherMessage));

        final var allPublicShares = tssShareExtractor.allPublicShares();
        assertNotNull(allPublicShares);
        assertEquals(GENESIS_SIZE * GENESIS_SHARES, allPublicShares.size());

        final var aggregatedPublicKey = TssPublicShare.aggregate(allPublicShares);
        assertNotNull(aggregatedPublicKey);

        final var privateShares = tssShareExtractor.ownedPrivateShares(myInfo);
        assertNotNull(privateShares);
        assertEquals(GENESIS_SHARES, privateShares.size());

        final var ownedPublicShares = myInfo.ownedShares(participantDirectory).stream()
                .map(share -> allPublicShares.get(share - 1))
                .toList();
        StreamUtils.zipStream(privateShares, ownedPublicShares)
                .forEach(e -> assertEquals(
                        e.getKey().privateKey().createPublicKey(), e.getValue().publicKey()));

        final var otherInfo = genesisCommittee.privateInfoOf(1);
        final var otherPrivateShares = tssService
                .genesisStage()
                .shareExtractor(participantDirectory, List.of(myMessage, otherMessage))
                .ownedPrivateShares(otherInfo);
        assertNotNull(otherPrivateShares);

        final var allPrivateShares = new ArrayList<>(privateShares);
        allPrivateShares.addAll(otherPrivateShares);
        final byte[] message = "MyMessage".getBytes();
        final var signatures =
                allPrivateShares.stream().map(share -> share.sign(message)).toList();

        StreamUtils.zipStream(signatures, allPublicShares)
                .forEach(e -> assertTrue(e.getKey().verify(e.getValue(), message)));

        final var aggregatedSignature = TssShareSignature.aggregate(signatures);

        assertTrue(aggregatedSignature.verify(aggregatedPublicKey, message));
    }

    @Test
    void testRekey() {
        final var self = 0;
        final var genesisCommittee = new TssTestCommittee(GENESIS_SIZE, GENESIS_SHARES, keys);

        final var genesisMessages = TssTestUtils.simulateGenesisMessaging(tssService, genesisCommittee);
        final var genesisShareExtractor = tssService
                .genesisStage()
                .shareExtractor(genesisCommittee.participantDirectory(), genesisMessages)
                .extract(genesisCommittee.privateInfoOf(self));

        final var pastPublicShares = genesisShareExtractor.allPublicShares();
        final var pastLedgerId = TssPublicShare.aggregate(pastPublicShares);
        final var allPrivateShares = genesisCommittee.allPrivateInfo().stream()
                .map(privateInfo -> tssService
                        .genesisStage()
                        .shareExtractor(genesisCommittee.participantDirectory(), genesisMessages)
                        .ownedPrivateShares(privateInfo))
                .toList();

        // *************** Rekey process
        final var targetCommittee = new TssTestCommittee(TARGET_SIZE, TARGET_SHARES, keys);
        final var rekeyMessages = TssTestUtils.simulateRekeyMessaging(tssService, targetCommittee, allPrivateShares);

        for (var message : rekeyMessages) {
            assertTrue(tssService
                    .rekeyStage()
                    .verifyTssMessage(targetCommittee.participantDirectory(), pastPublicShares, message));
        }

        final var tssShareExtractor =
                tssService.rekeyStage().shareExtractor(targetCommittee.participantDirectory(), rekeyMessages);

        final var selectedParticipantPrivateInfo = targetCommittee.privateInfoOf(self);
        tssShareExtractor.extract(selectedParticipantPrivateInfo);
        final var privateShares = tssShareExtractor.ownedPrivateShares(selectedParticipantPrivateInfo);
        final var publicShares = tssShareExtractor.allPublicShares();
        assertNotNull(privateShares);
        assertNotNull(publicShares);
        final var ownedPublicShares =
                selectedParticipantPrivateInfo.ownedShares(targetCommittee.participantDirectory()).stream()
                        .map(share -> publicShares.get(share - 1))
                        .toList();

        StreamUtils.zipStream(privateShares, ownedPublicShares)
                .forEach(e -> assertEquals(
                        e.getKey().privateKey().createPublicKey(), e.getValue().publicKey()));
        final var rekeyedLedgerId = TssPublicShare.aggregate(publicShares);
        assertEquals(pastLedgerId, rekeyedLedgerId);
    }
}
