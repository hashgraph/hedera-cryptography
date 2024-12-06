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
import com.hedera.cryptography.tss.extensions.serialization.TssMessageSerializers;
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
            @NonNull final SignatureSchema signatureSchema, @NonNull final Random rng, final int n) {
        return IntStream.range(0, n)
                .boxed()
                .map(i -> BlsPrivateKey.create(signatureSchema, rng))
                .toArray(BlsPrivateKey[]::new);
    }

    /**
     * Generates a {@link TssMessage} from 0 values
     */
    @NonNull
    public static TssMessage testTssMessage(
            @NonNull final SignatureSchema signatureSchema,
            final int generatingShare,
            final int totalShares,
            final int threshold) {
        final var zero = signatureSchema.getPairingFriendlyCurve().field().fromLong(0);
        final int n = signatureSchema.getPairingFriendlyCurve().field().elementSize();
        final var zeroElement = signatureSchema.getPublicKeyGroup().zero();
        final var zeros = Collections.nCopies(n, zeroElement);
        final var commitmentCoefficients = Collections.nCopies(threshold, zeroElement);
        return new TssMessage() {
            @Override
            public byte[] toBytes() {
                return TssMessageSerializers.defaultSerializer(signatureSchema).serialize(this);
            }

            @NonNull
            @Override
            public Integer generatingShare() {
                return generatingShare;
            }

            @NonNull
            @Override
            public List<GroupElement> sharedRandomness() {
                return zeros;
            }

            @NonNull
            @Override
            public List<List<GroupElement>> shareCiphertexts() {
                return Collections.nCopies(totalShares, zeros);
            }

            @NonNull
            @Override
            public List<GroupElement> polynomialCommitments() {
                return commitmentCoefficients;
            }

            @NonNull
            @Override
            public GroupElement f() {
                return zeroElement;
            }

            @NonNull
            @Override
            public GroupElement a() {
                return zeroElement;
            }

            @NonNull
            @Override
            public GroupElement y() {
                return zeroElement;
            }

            @NonNull
            @Override
            public FieldElement zR() {
                return zero;
            }

            @NonNull
            @Override
            public FieldElement zA() {
                return zero;
            }
        };
    }

    /**
     * Generates all random privateShares for each participant in the committee
     */
    @NonNull
    public static List<List<TssPrivateShare>> randomPrivateShares(
            @NonNull final TssTestCommittee committee,
            @NonNull final Random rng,
            @NonNull final SignatureSchema signatureSchema) {
        final var pks = rndSks(signatureSchema, rng, committee.size() * committee.sharesPerParticipant());
        return IntStream.range(0, committee.size())
                .mapToObj(i -> IntStream.range(0, committee.sharesPerParticipant())
                        .map(j -> i * committee.sharesPerParticipant() + j)
                        .mapToObj(j -> new TssPrivateShare(j + 1, pks[j]))
                        .toList())
                .toList();
    }
}
