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

import static com.hedera.cryptography.tss.test.fixtures.DkgUtils.rndSks;
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
import com.hedera.cryptography.tss.api.TssShareSignature;
import com.hedera.cryptography.tss.test.fixtures.DkgCommittee;
import com.hedera.cryptography.tss.test.fixtures.DkgUtils;
import com.hedera.cryptography.tss.test.fixtures.TestTssServiceImpl;
import com.hedera.cryptography.utils.test.fixtures.stream.StreamUtils;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A test to showcase the Tss protocol for a specific use-case
 */
class TssTest {

    public static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);
    public static final Random TEST_RNG = new Random();
    public static final int GENESIS_SIZE = 2;
    public static final int GENESIS_SHARES = 5;
    public static final int TARGET_SIZE = 4;
    public static final int TARGET_SHARES = 5;

    private BlsPrivateKey[] keys;
    private TssService tssService;

    @BeforeEach
    void setup() {
        Random rng = new Random(TEST_RNG.nextInt());
        keys = rndSks(SIGNATURE_SCHEMA, rng, Math.max(GENESIS_SIZE, TARGET_SIZE));
        tssService = new TestTssServiceImpl(SIGNATURE_SCHEMA);
    }

    @Test
    void testGenesis() {
        var genesisCommittee = new DkgCommittee(GENESIS_SIZE, GENESIS_SHARES, keys);
        var myDirectory = genesisCommittee.directoryFor(SIGNATURE_SCHEMA, 1);
        var myMessage = tssService.genesisStage().generateTssMessage(myDirectory);
        assertNotNull(myMessage);
        assertNotNull(tssService.messageFromBytes(myMessage.bytes()));
        final var otherDirectory = genesisCommittee.directoryFor(SIGNATURE_SCHEMA, 2);
        assertTrue(tssService.genesisStage().verifyTssMessage(otherDirectory, myMessage));
        var otherMessage = tssService.genesisStage().generateTssMessage(myDirectory);

        final var allPublicShares =
                tssService.genesisStage().obtainPublicShares(myDirectory, List.of(myMessage, otherMessage));
        assertNotNull(allPublicShares);
        assertEquals(GENESIS_SIZE * GENESIS_SHARES, allPublicShares.size());

        final BlsPublicKey aggregatedPublicKey = TssPublicShare.aggregate(allPublicShares);
        assertNotNull(aggregatedPublicKey);

        final var privateShares =
                tssService.genesisStage().obtainPrivateShares(myDirectory, List.of(myMessage, otherMessage));
        assertNotNull(privateShares);
        assertEquals(GENESIS_SHARES, privateShares.size());

        var ownedPublicShares = myDirectory.getOwnedShareIds().stream()
                .map(share -> allPublicShares.get(share - 1))
                .toList();
        StreamUtils.zipStream(privateShares, ownedPublicShares)
                .forEach(e -> assertEquals(
                        e.getKey().privateKey().createPublicKey(), e.getValue().publicKey()));

        final var otherPrivateShares =
                tssService.genesisStage().obtainPrivateShares(otherDirectory, List.of(myMessage, otherMessage));
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
    void testRekey() {
        var genesisCommittee = new DkgCommittee(GENESIS_SIZE, GENESIS_SHARES, keys);
        var targetCommittee = new DkgCommittee(TARGET_SIZE, TARGET_SHARES, keys);

        var setupGenesis = DkgUtils.setupGenesis(tssService, SIGNATURE_SCHEMA, genesisCommittee);
        var pastPublicShares = setupGenesis.obtainPublicShares(tssService.genesisStage());
        var pastLedgerId = TssPublicShare.aggregate(pastPublicShares);
        var allPastPrivateShares = setupGenesis.retrieveAllPrivateShares(tssService.genesisStage(), genesisCommittee);

        var setupRekey = DkgUtils.setupRekey(tssService, SIGNATURE_SCHEMA, targetCommittee, allPastPrivateShares);
        var presentDirectory = setupRekey.dirs().getFirst();
        for (var message : setupRekey.validMessages()) {
            assertTrue(tssService.rekeyStage().verifyTssMessage(presentDirectory, pastPublicShares, message));
        }
        var privateShares = tssService.rekeyStage().obtainPrivateShares(presentDirectory, setupRekey.validMessages());
        var publicShares = tssService.rekeyStage().obtainPublicShares(presentDirectory, setupRekey.validMessages());
        assertNotNull(privateShares);
        assertNotNull(publicShares);
        var ownedPublicShares = presentDirectory.getOwnedShareIds().stream()
                .map(share -> publicShares.get(share - 1))
                .toList();

        StreamUtils.zipStream(privateShares, ownedPublicShares)
                .forEach(e -> assertEquals(
                        e.getKey().privateKey().createPublicKey(), e.getValue().publicKey()));
        var rekeyedLedgerId = TssPublicShare.aggregate(publicShares);
        assertEquals(pastLedgerId, rekeyedLedgerId);
    }
}
