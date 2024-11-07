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

package com.hedera.cryptography.tss.test.fixtures;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssServiceStage;
import com.hedera.cryptography.utils.ByteArrayUtils.Serializer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Set of utility methods that provides helper functionality to set up tests.
 */
public class DkgUtils {
    /**
     * Simulates the execution of a genesis stage and collects tssMessages.
     * Provides the messages and the directories associated to the committee
     */
    public static DkgSetup setupGenesis(
            final TssService tssService, final SignatureSchema signatureSchema, final DkgCommittee dkgCommittee) {
        var dirs = dkgCommittee.allDirectories(signatureSchema);

        var tssMessages = dirs.stream()
                .parallel()
                .limit(dkgCommittee.threshold())
                .map(dir -> tssService.genesisStage().generateTssMessage(dir))
                .toList();
        return new DkgSetup(tssMessages, dirs);
    }

    /**
     * Simulates the execution of a rekey stage
     * Provides the messages and the directories associated to the committee
     */
    public static DkgSetup setupRekey(
            final TssService tssService,
            final SignatureSchema signatureSchema,
            final DkgCommittee dkgCommittee,
            final Map<Long, List<TssPrivateShare>> privateShares) {
        var dirs = dkgCommittee.allDirectories(signatureSchema);
        var tssMessages = privateShares.entrySet().stream()
                .parallel()
                .flatMap(entry -> {
                    var participant = dirs.get(entry.getKey().intValue());
                    var ps = entry.getValue();
                    return ps.stream().parallel().map(privateShare -> tssService
                            .genesisStage()
                            .generateTssMessage(participant, privateShare));
                })
                .limit(dkgCommittee.threshold())
                .toList();

        return new DkgSetup(tssMessages, dirs);
    }

    /**
     * Generates an array of n random BlsPrivateKey
     */
    public static BlsPrivateKey[] rndSks(final SignatureSchema signatureSchema, final Random rng, int n) {
        return IntStream.range(0, n)
                .boxed()
                .map(i -> BlsPrivateKey.create(signatureSchema, rng))
                .toArray(BlsPrivateKey[]::new);
    }

    /**
     * Generates an array of n fixed value BlsPrivateKey
     */
    public static BlsPrivateKey[] fixedSk(final SignatureSchema signatureSchema, long fixedValue, final int n) {
        var val = signatureSchema.getPairingFriendlyCurve().field().fromLong(fixedValue);
        var keys = new BlsPrivateKey[n];
        Arrays.fill(keys, new BlsPrivateKey(val, signatureSchema));
        return keys;
    }

    /**
     * Generates a 0 value {@link TssMessage}
     */
    public static TssMessage testTssMessage(
            SignatureSchema signatureSchema, int generatingShare, int totalShares, int threshold) {
        final FieldElement zero =
                signatureSchema.getPairingFriendlyCurve().field().fromLong(0);
        final int n = signatureSchema.getPairingFriendlyCurve().field().elementSize();
        final GroupElement zeroElement = signatureSchema.getPublicKeyGroup().zero();
        final var zeros = Collections.nCopies(n, zeroElement);
        final var commitmentCoefficients = Collections.nCopies(threshold, zeroElement);

        var serializer = new Serializer()
                .put(TssMessage.MESSAGE_CURRENT_VERSION)
                .put(signatureSchema.getIdByte())
                .put(generatingShare)
                .putListSameSize(zeros, GroupElement::toBytes)
                .put(totalShares);
        for (int i = 0; i < totalShares; i++) {
            serializer.putListSameSize(zeros, GroupElement::toBytes);
        }
        serializer
                .putListSameSize(commitmentCoefficients, GroupElement::toBytes)
                .put(zeroElement::toBytes)
                .put(zeroElement::toBytes)
                .put(zeroElement::toBytes)
                .put(zero::toBytes)
                .put(zero::toBytes);

        return new OpaqueTssMessage(serializer.toBytes());
    }

    /**
     * A record that represents the execution of a stage
     * @param validMessages
     * @param dirs
     */
    public record DkgSetup(List<TssMessage> validMessages, List<TssParticipantDirectory> dirs) {

        public List<TssPublicShare> obtainPublicShares(final TssServiceStage tssServiceStage) {
            return this.dirs.stream()
                    .findFirst()
                    .map(d -> tssServiceStage.obtainPublicShares(d, this.validMessages()))
                    .orElseThrow();
        }

        public Map<Long, List<TssPrivateShare>> retrieveAllPrivateShares(
                final TssServiceStage tssService, final DkgCommittee dkgCommittee) {
            return IntStream.range(0, dkgCommittee.size())
                    .boxed()
                    .parallel()
                    .collect(Collectors.toMap(
                            i -> (long) i,
                            participant ->
                                    tssService.obtainPrivateShares(this.dirs.get(participant), this.validMessages())));
        }
    }
}
