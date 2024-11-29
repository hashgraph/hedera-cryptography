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

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssMessageParsingException;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.impl.Groth21Service;
import com.hedera.cryptography.tss.test.fixtures.TssTestCommittee;
import com.hedera.cryptography.tss.test.fixtures.TssTestUtils;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Timeout;
import org.openjdk.jmh.annotations.Warmup;

/**
 * A test to showcase the Tss protocol for a specific case
 * More validations can be added once
 */
@State(Scope.Benchmark)
@Timeout(time = 10, timeUnit = TimeUnit.HOURS)
@Fork(value = 1, jvmArgsAppend = "-Xmx48g")
@Threads(10)
@Warmup(iterations = 0)
@Measurement(iterations = 1)
@BenchmarkMode(Mode.SingleShotTime)
@OutputTimeUnit(TimeUnit.SECONDS)
public class GenerateMessagesBenchmark {

    // ************************************************
    // COMPRESSED
    // Benchmark                                                (groupAssignment)  (participants)  (shares)  Mode  Cnt
    //  Score   Error  Units
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS             128         2    ss
    //  2.391           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES             128         2    ss
    //  6.363           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages  SHORT_PUBLIC_KEYS             128         2    ss
    // 72.449           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             128         2    ss
    // 198.247           s/op

    //
    // Benchmark                                                (groupAssignment)  (participants)  (shares)  Mode  Cnt
    //  Score   Error  Units
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS             256         2    ss
    //  4.902           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES             256         2    ss
    // 12.882           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages  SHORT_PUBLIC_KEYS             256         2    ss
    // 287.540           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             256         2    ss
    // 792.447           s/op

    // Benchmark                                                (groupAssignment)  (participants)  (shares)  Mode  Cnt
    //   Score   Error  Units
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS             512         2    ss
    //  10.450           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES             512         2    ss
    //  27.221           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages  SHORT_PUBLIC_KEYS             512         2    ss
    // 1151.315           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             512         2    ss
    // 3143.904           s/op

    // ************************************************
    // UN-COMPRESSED

    // Benchmark                                                (groupAssignment)  (participants)  (shares)  Mode  Cnt
    //  Score   Error  Units
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS             128         2    ss
    //  1.714           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES             128         2    ss
    //  4.006           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages  SHORT_PUBLIC_KEYS             128         2    ss
    // 65.922           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             128         2    ss
    // 175.585           s/op

    // Benchmark                                                (groupAssignment)  (participants)  (shares)  Mode  Cnt
    //  Score   Error  Units
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS             256         2    ss
    //  3.558           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES             256         2    ss
    //  8.243           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages  SHORT_PUBLIC_KEYS             256         2    ss
    // 262.770           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             256         2    ss
    // 700.824           s/op

    // Benchmark                                                (groupAssignment)  (participants)  (shares)  Mode  Cnt
    //   Score   Error  Units
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS             512         2    ss
    //   7.643           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES             512         2    ss
    //  16.985           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages  SHORT_PUBLIC_KEYS             512         2    ss
    // 1041.317           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             512         2    ss
    // 2790.024           s/op

    public static final Random TEST_RNG = new Random();
    public static Random rng = new Random(TEST_RNG.nextInt());
    static SignatureSchema signatureSchema;

    @Param({"SHORT_PUBLIC_KEYS", "SHORT_SIGNATURES"})
    static GroupAssignment groupAssignment;

    @Param({"512"})
    static int participants;

    @Param({"2"})
    static int shares;

    TssService tssService;
    TssTestCommittee genesisCommittee;

    @Setup
    public void setup() {
        signatureSchema = SignatureSchema.create(Curve.ALT_BN128, groupAssignment);
        tssService = new Groth21Service(signatureSchema, rng);
        final BlsPrivateKey[] keys = TssTestUtils.rndSks(signatureSchema, rng, participants);
        genesisCommittee = new TssTestCommittee(participants, shares, keys);
    }

    @Benchmark
    public List<?> produceSharesNumberOfMessages() {
        List<byte[]> messages = new ArrayList<>(participants);
        for (int i = 0; i < shares; i++) {
            messages.add(tssService
                    .genesisStage()
                    .generateTssMessage(genesisCommittee.participantDirectory())
                    .toBytes());
        }

        return messages;
    }

    @Benchmark
    public List<?> readThresholdNumberOfMessages(ReadMessageState state) {
        List<TssMessage> tssMessages = new ArrayList<>(participants);
        for (byte[] message : state.messages) {
            try {
                tssMessages.add(tssService.messageFromBytes(genesisCommittee.participantDirectory(), message));
            } catch (TssMessageParsingException e) {
                throw new RuntimeException(e);
            }
        }
        return tssMessages;
    }

    @State(Scope.Benchmark)
    public static class ReadMessageState {
        List<byte[]> messages;
        TssService tssService;
        TssTestCommittee genesisCommittee;

        @Setup
        public void setup() {
            signatureSchema = SignatureSchema.create(Curve.ALT_BN128, groupAssignment);
            tssService = new Groth21Service(signatureSchema, rng);
            final BlsPrivateKey[] keys = TssTestUtils.rndSks(signatureSchema, rng, participants);
            genesisCommittee = new TssTestCommittee(participants, shares, keys);
            var privateSharesPerParticipant = TssTestUtils.randomPrivateShares(genesisCommittee, rng, signatureSchema);
            this.messages =
                    TssTestUtils.simulateRekeyMessaging(tssService, genesisCommittee, privateSharesPerParticipant)
                            .stream()
                            .parallel()
                            .map(TssMessage::toBytes)
                            .toList();
        }
    }
}
