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

import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssMessageParsingException;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.extensions.serialization.DefaultTssMessageSerialization;
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
import org.openjdk.jmh.annotations.Warmup;

/**
 * A test to showcase the Tss protocol for a specific case
 * More validations can be added once
 */
@Warmup(iterations = 1, time = 10, timeUnit = TimeUnit.MILLISECONDS)
@Threads(2)
@Fork(1)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class TssMessageBenchmark {
    public static final Random TEST_RNG = new Random();
    public static Random rng = new Random(TEST_RNG.nextInt());
    static SignatureSchema signatureSchema;

    @Param({"SHORT_SIGNATURES"})
    static GroupAssignment groupAssignment;

    @Param({"130"})
    static int participants;

    @Param({"10"})
    static int shares;
    // Not Compressed
    // Benchmark                                 (groupAssignment)  (participants)  (shares)  Mode  Cnt      Score
    // Error  Units
    // TssMessageBenchmark.generateTssMessage     SHORT_SIGNATURES             130        10  avgt    5  10062.937 ±
    // 231.176  ms/op
    // TssMessageBenchmark.readMessageFromBytes   SHORT_SIGNATURES             130        10  avgt    5   6609.734 ±
    // 63.208  ms/op
    // Comprssed:
    // Benchmark                                 (groupAssignment)  (participants)  (shares)  Mode  Cnt      Score
    // Error  Units
    // TssMessageBenchmark.generateTssMessage     SHORT_SIGNATURES             130        10  avgt    5  10171.065 ±
    // 500.945  ms/op
    // TssMessageBenchmark.readMessageFromBytes   SHORT_SIGNATURES             130        10  avgt    5   7498.260 ±
    // 214.705  ms/op

    @Benchmark
    public Object generateTssMessage(ReadMessagesState state) {
        return state.tssService.genesisStage().generateTssMessage(state.genesisCommittee.participantDirectory());
    }

    @Benchmark
    public Object defaultDeserialize(ReadUncompressedMessageState state) {
        return DefaultTssMessageSerialization.getDeserializer(
                        signatureSchema, state.genesisCommittee.participantDirectory())
                .deserialize(state.message);
    }

    @Benchmark
    public Object nonValidatedDeserialize(ReadUncompressedMessageState state) {
        return DefaultTssMessageSerialization.getNonValidatedDeserializer(
                        signatureSchema, state.genesisCommittee.participantDirectory())
                .deserialize(state.message);
    }

    @Benchmark
    public Object compressDeserialize(ReadCompressedMessageState state) {
        return DefaultTssMessageSerialization.getCompressedDeserializer(
                        signatureSchema, state.genesisCommittee.participantDirectory())
                .deserialize(state.message);
    }

    @BenchmarkMode(Mode.SingleShotTime)
    @Warmup(iterations = 0)
    @Threads(1)
    @Measurement(iterations = 1)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Benchmark
    public List<?> readThresholdNumberOfMessages(ReadMessagesState state) {
        List<TssMessage> tssMessages = new ArrayList<>(participants);
        final int size = state.messages.length;
        for (int i = 0; i < size; i++) {
            try {
                tssMessages.add(state.tssService.messageFromBytes(
                        state.genesisCommittee.participantDirectory(), state.messages[i]));
                state.messages[i] = null;
            } catch (TssMessageParsingException e) {
                throw new RuntimeException(e);
            }
        }
        return tssMessages;
    }

    public abstract static class GenericAbstractState {
        protected TssService tssService;
        protected TssTestCommittee genesisCommittee;

        public void setup() {
            signatureSchema = SignatureSchema.create(Curve.ALT_BN128, groupAssignment);
            tssService = new Groth21Service(signatureSchema, rng);
            final var keys = TssTestUtils.rndSks(signatureSchema, rng, participants);
            genesisCommittee = new TssTestCommittee(participants, shares, keys);
        }
    }

    @State(Scope.Benchmark)
    public static class GenerateMessagesState extends GenericAbstractState {
        @Setup
        public void setup() {
            super.setup();
        }
    }

    @State(Scope.Benchmark)
    public static class ReadUncompressedMessageState extends GenericAbstractState {
        byte[] message;

        @Setup
        public void setup() {
            super.setup();
            this.message = DefaultTssMessageSerialization.getSerializer(signatureSchema)
                    .serialize(tssService.genesisStage().generateTssMessage(genesisCommittee.participantDirectory()));
        }
    }

    @State(Scope.Benchmark)
    public static class ReadCompressedMessageState extends GenericAbstractState {
        byte[] message;

        @Setup
        public void setup() {
            super.setup();
            this.message = DefaultTssMessageSerialization.getCompressedSerializer(signatureSchema)
                    .serialize(tssService.genesisStage().generateTssMessage(genesisCommittee.participantDirectory()));
        }
    }

    @State(Scope.Benchmark)
    public static class ReadMessagesState extends ReadUncompressedMessageState {
        byte[][] messages;

        @Setup
        public void setup() {
            super.setup();
            byte[][] matrix = new byte[genesisCommittee.threshold()][];
            for (int i = 0; i < genesisCommittee.threshold(); i++) {
                matrix[i] = message;
            }
            messages = matrix;
        }
    }
}
