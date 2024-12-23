// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.tss.extensions;

import static com.hedera.cryptography.tss.test.fixtures.TssTestUtils.rndSks;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssParticipantPrivateInfo;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssShareExtractor;
import com.hedera.cryptography.tss.api.TssShareSignature;
import com.hedera.cryptography.tss.extensions.serialization.DefaultTssMessageSerialization;
import com.hedera.cryptography.tss.impl.Groth21Service;
import com.hedera.cryptography.tss.test.fixtures.TssTestCommittee;
import com.hedera.cryptography.tss.test.fixtures.TssTestUtils;
import com.hedera.cryptography.tss.test.fixtures.beaver.Beaver;
import com.hedera.cryptography.utils.test.fixtures.rng.SeededRandom;
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
    void testToBytesAndBackAgain() {
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
    void testGenesisWithBeaver() throws Exception {
        new Beaver(new SeededRandom())
                .withCommittee()
                .randomKeys()
                .withCommitteeSize(GENESIS_SIZE, GENESIS_SHARES)
                .and()
                .withTssService(SERVICE)
                .genesis()
                .senders(0, 1)
                .test()
                .assertEqualLedgerIds(0, 1)
                .retrievePrivateShare(0, (extractor, directory, allPublicShares, info) -> {
                    final var privateShares = extractor.ownedPrivateShares(info);
                    assertNotNull(privateShares);
                    assertEquals(GENESIS_SHARES, privateShares.size());

                    final var ownedPublicShares = info.ownedShares(directory).stream()
                            .map(share -> allPublicShares.get(share - 1))
                            .toList();
                    StreamUtils.zipStream(privateShares, ownedPublicShares)
                            .forEach(e -> assertEquals(
                                    e.getKey().privateKey().createPublicKey(),
                                    e.getValue().publicKey()));
                })
                .retrievePrivateShare(1, (extractor, directory, allPublicShares, info) -> {
                    final var privateShares = extractor.ownedPrivateShares(info);
                    assertNotNull(privateShares);
                    assertEquals(GENESIS_SHARES, privateShares.size());

                    final var ownedPublicShares = info.ownedShares(directory).stream()
                            .map(share -> allPublicShares.get(share - 1))
                            .toList();
                    StreamUtils.zipStream(privateShares, ownedPublicShares)
                            .forEach(e -> assertEquals(
                                    e.getKey().privateKey().createPublicKey(),
                                    e.getValue().publicKey()));
                });
    }

    @Test
    void testGenesis() {
        // Setup
        final var genesisCommittee = new TssTestCommittee(GENESIS_SIZE, GENESIS_SHARES, keys);
        final TssParticipantDirectory participantDirectory = genesisCommittee.participantDirectory();
        final var myMessage = tssService.genesisStage().generateTssMessage(participantDirectory);
        assertNotNull(myMessage);
        final var serializer = DefaultTssMessageSerialization.getSerializer(SIGNATURE_SCHEMA);
        assertNotNull(DefaultTssMessageSerialization.getDeserializer(SIGNATURE_SCHEMA, participantDirectory)
                .deserialize(serializer.serialize(myMessage)));
        final var otherMessage = tssService.genesisStage().generateTssMessage(participantDirectory);
        final TssShareExtractor tssShareExtractor =
                tssService.genesisStage().shareExtractor(participantDirectory, List.of(myMessage, otherMessage));

        // Genesis start
        final var allPublicShares = tssShareExtractor.allPublicShares();
        assertNotNull(allPublicShares);
        assertEquals(GENESIS_SIZE * GENESIS_SHARES, allPublicShares.size()); // Number of shares of all participants

        final var aggregatedPublicKey = TssPublicShare.aggregate(allPublicShares);
        assertNotNull(aggregatedPublicKey);

        // Validate participant's private shares (different method)
        final TssParticipantPrivateInfo myInfo = genesisCommittee.privateInfoOf(0);
        final var privateShares = tssShareExtractor.ownedPrivateShares(myInfo);
        assertNotNull(privateShares);
        assertEquals(GENESIS_SHARES, privateShares.size());

        final var ownedPublicShares = myInfo.ownedShares(participantDirectory).stream()
                .map(share -> allPublicShares.get(share - 1))
                .toList();
        StreamUtils.zipStream(privateShares, ownedPublicShares)
                .forEach(e -> assertEquals(
                        e.getKey().privateKey().createPublicKey(), e.getValue().publicKey()));

        // Validate participant's private shares (same method)
        final var otherInfo = genesisCommittee.privateInfoOf(1);
        final var otherPrivateShares = tssService
                .genesisStage()
                .shareExtractor(participantDirectory, List.of(myMessage, otherMessage))
                .ownedPrivateShares(otherInfo);
        assertNotNull(otherPrivateShares);

        final var allPrivateShares = new ArrayList<>(privateShares);
        allPrivateShares.addAll(otherPrivateShares);

        // Validating signatures and message
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
