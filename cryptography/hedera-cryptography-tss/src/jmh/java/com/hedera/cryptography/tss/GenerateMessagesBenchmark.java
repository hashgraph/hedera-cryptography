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
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
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
public class GenerateMessagesBenchmark {
    // Benchmark                                                (groupAssignment)  (participants)  (shares)  Mode  Cnt
    //  Score   Error  Units
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES             128         2    ss
    //  6.364           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES            1024         2    ss
    // 55.465           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS             128         2    ss
    //  2.378           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS            1024         2    ss
    // 23.811           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             128         2    ss
    // 197.614           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages  SHORT_PUBLIC_KEYS             128         2    ss
    // 73.364           s/op

    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS            1024         2    ss
    // 23.307           s/op

    // Benchmark                                                (groupAssignment)  (participants)  (shares)  Mode  Cnt
    //  Score   Error  Units
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS             256         2    ss
    //  3.502           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES             256         2    ss
    //  8.131           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages  SHORT_PUBLIC_KEYS             256         2    ss
    // 261.560           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             256         2    ss
    // 696.375           s/op

    // Benchmark                                                (groupAssignment)  (participants)  (shares)  Mode  Cnt
    //  Score   Error  Units
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS             128         2    ss
    //  1.702           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES             128         2    ss
    //  3.986           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages  SHORT_PUBLIC_KEYS             128         2    ss
    // 65.462           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             128         2    ss
    // 174.767           s/op

    // Benchmark                                                (groupAssignment)  (participants)  (shares)  Mode  Cnt
    //   Score   Error  Units
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages  SHORT_PUBLIC_KEYS             512         2    ss
    //   7.593           s/op
    // GenerateMessagesBenchmark.produceSharesNumberOfMessages   SHORT_SIGNATURES             512         2    ss
    //  16.931           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages  SHORT_PUBLIC_KEYS             512         2    ss
    // 1039.990           s/op
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             512         2    ss
    // 2774.135           s/op

    // COMPRESSED: Benchmark 130x10                                                (groupAssignment)  (participants)
    // (shares)  Mode  Cnt     Score   Error  Units
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             130        10    ss
    // 4191.890           s/op
    // UN COMPRESED Benchmark 130x10                                               (groupAssignment)  (participants)
    // (shares)  Mode  Cnt     Score   Error  Units
    // GenerateMessagesBenchmark.readThresholdNumberOfMessages   SHORT_SIGNATURES             130        10    ss
    // 4241.999           s/op
    public static final Random TEST_RNG = new Random();
    public static Random rng = new Random(TEST_RNG.nextInt());
    static SignatureSchema signatureSchema;

    @Param({"SHORT_SIGNATURES"})
    static GroupAssignment groupAssignment;

    @Param({"130"})
    static int participants;

    @Param({"10"})
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
    @BenchmarkMode(Mode.All)
    @Warmup(iterations = 1, time = 10, timeUnit = TimeUnit.MILLISECONDS)
    @Threads(2)
    @Fork(1)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public Object readMessages(ReadMessageState state) throws TssMessageParsingException {
        return com.hedera.cryptography.tss.impl.groth21.Groth21Message.fromBytes(
                state.messages[0], state.directory, signatureSchema);
    }

    @Benchmark
    @BenchmarkMode(Mode.SingleShotTime)
    @Warmup(iterations = 0)
    @Threads(1)
    @Measurement(iterations = 1)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public List<?> readThresholdNumberOfMessages(ReadMessageState state) {
        List<TssMessage> tssMessages = new ArrayList<>(participants);
        final int size = state.messages.length;
        for (int i = 0; i < size; i++) {
            try {
                tssMessages.add(tssService.messageFromBytes(state.directory, state.messages[i]));
                state.messages[i] = null;
            } catch (TssMessageParsingException e) {
                throw new RuntimeException(e);
            }
        }
        return tssMessages;
    }

    @State(Scope.Benchmark)
    public static class ReadMessageState {
        byte[][] messages;
        TssService tssService;
        TssTestCommittee genesisCommittee;
        TssParticipantDirectory directory;

        @Setup
        public void setup() {
            signatureSchema = SignatureSchema.create(Curve.ALT_BN128, groupAssignment);
            tssService = new Groth21Service(signatureSchema, rng);
            final BlsPrivateKey[] keys = TssTestUtils.rndSks(signatureSchema, rng, participants);
            genesisCommittee = new TssTestCommittee(participants, shares, keys);
            directory = genesisCommittee.participantDirectory();
            var value = tssService
                    .genesisStage()
                    .generateTssMessage(genesisCommittee.participantDirectory())
                    .toBytes();
            byte[][] matrix = new byte[genesisCommittee.threshold()][];
            for (int i = 0; i < genesisCommittee.threshold(); i++) {
                matrix[i] = value;
            }
            messages = matrix;
        }
    }
}
