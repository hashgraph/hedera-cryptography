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
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.utils.ByteArrayUtils.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;

/**
 * Set of utility methods that provides helper functionality to set up tests.
 */
public class TssTestUtils {
    /**
     * Simulates the execution of a genesis stage and collects tssMessages.
     * @return the messages
     */
    @NonNull
    public static List<TssMessage> simulateGenesisMessaging(
            @NonNull final TssService tssService, @NonNull final TssTestCommittee tssTestCommittee) {
        final var dir = tssTestCommittee.participantDirectory();
        return IntStream.range(0, dir.getThreshold())
                .parallel()
                .mapToObj(i -> tssService.genesisStage().generateTssMessage(dir))
                .toList();
    }

    /**
     * Simulates the execution of a rekey stage
     * @return the messages
     */
    @NonNull
    public static List<TssMessage> simulateRekeyMessaging(
            @NonNull final TssService tssService,
            @NonNull final TssTestCommittee tssTestCommittee,
            @NonNull final List<List<TssPrivateShare>> privateShares) {
        final var dir = tssTestCommittee.participantDirectory();
        return privateShares.stream()
                .parallel()
                .limit(tssTestCommittee.threshold())
                .flatMap(entry -> entry.stream()
                        .parallel()
                        .limit(tssTestCommittee.threshold())
                        .map(privateShare -> tssService.rekeyStage().generateTssMessage(dir, privateShare)))
                .limit(tssTestCommittee.threshold())
                .toList();
    }

    /**
     * Generates an array of n random BlsPrivateKey
     *
     * @return an array of n random BlsPrivateKey
     */
    @NonNull
    public static BlsPrivateKey[] rndSks(
            @NonNull final SignatureSchema signatureSchema, @NonNull final Random rng, int n) {
        return IntStream.range(0, n)
                .boxed()
                .map(i -> BlsPrivateKey.create(signatureSchema, rng))
                .toArray(BlsPrivateKey[]::new);
    }

    /**
     * Generates a 0 value {@link TssMessage}
     */
    @NonNull
    public static TssMessage testTssMessage(
            @NonNull final SignatureSchema signatureSchema,
            final int generatingShare,
            final int totalShares,
            final int threshold) {
        final FieldElement zero =
                signatureSchema.getPairingFriendlyCurve().field().fromLong(0);
        final int n = signatureSchema.getPairingFriendlyCurve().field().elementSize();
        final var zeroElement = signatureSchema.getPublicKeyGroup().zero();
        final var zeros = Collections.nCopies(n, zeroElement);
        final var commitmentCoefficients = Collections.nCopies(threshold, zeroElement);

        final var serializer = new Serializer()
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

    public static List<List<TssPrivateShare>> randomPrivateShares(
            final TssTestCommittee committee, final Random rng, SignatureSchema signatureSchema) {
        final var pks = rndSks(signatureSchema, rng, committee.size() * committee.sharesPerParticipant());
        return IntStream.range(0, committee.size())
                .mapToObj(i -> IntStream.range(0, committee.sharesPerParticipant())
                        .map(j -> i * committee.size() + j)
                        .mapToObj(j -> new TssPrivateShare(j, pks[j]))
                        .toList())
                .toList();
    }
}
