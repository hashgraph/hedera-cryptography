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
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.BlsSignature;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.tss.api.TssParticipantPrivateInfo;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssShareExtractor;
import com.hedera.cryptography.tss.api.TssShareSignature;
import com.hedera.cryptography.tss.impl.Groth21Service;
import com.hedera.cryptography.tss.test.fixtures.TssTestCommittee;
import com.hedera.cryptography.tss.test.fixtures.TssTestUtils;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
public class TssBenchmark {

    public static final Random TEST_RNG = new Random();
    public static Random rng = new Random(TEST_RNG.nextInt());

    @Param({"P100S1", "P100S3", "P100S5", "P100S10", "P130S10"})
    static String benchmarkTest;

    @Param({"SHORT_SIGNATURES", "SHORT_PUBLIC_KEYS"})
    static GroupAssignment groupAssignment;

    static SignatureSchema signatureSchema;

    @Setup
    public void setup() {
        signatureSchema = SignatureSchema.create(Curve.ALT_BN128, groupAssignment);
    }

    // Benchmark                                (benchmarkTest)  (groupAssignment)  (messageSize)  Mode  Cnt     Score
    // Error  Units
    // TssBenchmark.genesisObtainPrivateShares           P100S1   SHORT_SIGNATURES            N/A    ss          0.339
    //         s/op
    // TssBenchmark.genesisObtainPrivateShares           P100S1  SHORT_PUBLIC_KEYS            N/A    ss          0.130
    //         s/op
    // TssBenchmark.genesisObtainPrivateShares           P100S3   SHORT_SIGNATURES            N/A    ss          3.117
    //         s/op
    // TssBenchmark.genesisObtainPrivateShares           P100S3  SHORT_PUBLIC_KEYS            N/A    ss          1.160
    //         s/op
    // TssBenchmark.genesisObtainPrivateShares           P100S5   SHORT_SIGNATURES            N/A    ss          8.643
    //         s/op
    // TssBenchmark.genesisObtainPrivateShares           P100S5  SHORT_PUBLIC_KEYS            N/A    ss          3.094
    //         s/op
    // TssBenchmark.genesisObtainPrivateShares          P100S10   SHORT_SIGNATURES            N/A    ss         30.192
    //         s/op
    // TssBenchmark.genesisObtainPrivateShares          P100S10  SHORT_PUBLIC_KEYS            N/A    ss         12.788
    //         s/op
    // TssBenchmark.genesisObtainPrivateShares          P130S10   SHORT_SIGNATURES            N/A    ss         42.122
    //         s/op
    // TssBenchmark.genesisObtainPrivateShares          P130S10  SHORT_PUBLIC_KEYS            N/A    ss         16.104
    //         s/op
    // TssBenchmark.genesisObtainPublicShares            P100S1   SHORT_SIGNATURES            N/A    ss          3.043
    //         s/op
    // TssBenchmark.genesisObtainPublicShares            P100S1  SHORT_PUBLIC_KEYS            N/A    ss          2.172
    //         s/op
    // TssBenchmark.genesisObtainPublicShares            P100S3   SHORT_SIGNATURES            N/A    ss         89.245
    //         s/op
    // TssBenchmark.genesisObtainPublicShares            P100S3  SHORT_PUBLIC_KEYS            N/A    ss         60.999
    //         s/op
    // TssBenchmark.genesisObtainPublicShares            P100S5   SHORT_SIGNATURES            N/A    ss        433.085
    //         s/op
    // TssBenchmark.genesisObtainPublicShares            P100S5  SHORT_PUBLIC_KEYS            N/A    ss        283.260
    //         s/op
    // TssBenchmark.genesisObtainPublicShares           P100S10   SHORT_SIGNATURES            N/A    ss       3669.155
    //         s/op
    // TssBenchmark.genesisObtainPublicShares           P100S10  SHORT_PUBLIC_KEYS            N/A    ss       2382.951
    //         s/op
    // TssBenchmark.genesisObtainPublicShares           P130S10   SHORT_SIGNATURES            N/A    ss       8109.137
    //         s/op
    // TssBenchmark.genesisObtainPublicShares           P130S10  SHORT_PUBLIC_KEYS            N/A    ss       5226.440
    //         s/op
    // TssBenchmark.p0Signs                              P100S1   SHORT_SIGNATURES             32    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S1   SHORT_SIGNATURES            256    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S1   SHORT_SIGNATURES           1024    ss         ≈ 10⁻³
    //         s/op
    // TssBenchmark.p0Signs                              P100S1  SHORT_PUBLIC_KEYS             32    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S1  SHORT_PUBLIC_KEYS            256    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S1  SHORT_PUBLIC_KEYS           1024    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S3   SHORT_SIGNATURES             32    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S3   SHORT_SIGNATURES            256    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S3   SHORT_SIGNATURES           1024    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S3  SHORT_PUBLIC_KEYS             32    ss          0.002
    //         s/op
    // TssBenchmark.p0Signs                              P100S3  SHORT_PUBLIC_KEYS            256    ss          0.002
    //         s/op
    // TssBenchmark.p0Signs                              P100S3  SHORT_PUBLIC_KEYS           1024    ss          0.002
    //         s/op
    // TssBenchmark.p0Signs                              P100S5   SHORT_SIGNATURES             32    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S5   SHORT_SIGNATURES            256    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S5   SHORT_SIGNATURES           1024    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                              P100S5  SHORT_PUBLIC_KEYS             32    ss          0.002
    //         s/op
    // TssBenchmark.p0Signs                              P100S5  SHORT_PUBLIC_KEYS            256    ss          0.002
    //         s/op
    // TssBenchmark.p0Signs                              P100S5  SHORT_PUBLIC_KEYS           1024    ss          0.002
    //         s/op
    // TssBenchmark.p0Signs                             P100S10   SHORT_SIGNATURES             32    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                             P100S10   SHORT_SIGNATURES            256    ss          0.002
    //         s/op
    // TssBenchmark.p0Signs                             P100S10   SHORT_SIGNATURES           1024    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                             P100S10  SHORT_PUBLIC_KEYS             32    ss          0.004
    //         s/op
    // TssBenchmark.p0Signs                             P100S10  SHORT_PUBLIC_KEYS            256    ss          0.004
    //         s/op
    // TssBenchmark.p0Signs                             P100S10  SHORT_PUBLIC_KEYS           1024    ss          0.004
    //         s/op
    // TssBenchmark.p0Signs                             P130S10   SHORT_SIGNATURES             32    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                             P130S10   SHORT_SIGNATURES            256    ss          0.001
    //         s/op
    // TssBenchmark.p0Signs                             P130S10   SHORT_SIGNATURES           1024    ss          0.002
    //         s/op
    // TssBenchmark.p0Signs                             P130S10  SHORT_PUBLIC_KEYS             32    ss          0.004
    //         s/op
    // TssBenchmark.p0Signs                             P130S10  SHORT_PUBLIC_KEYS            256    ss          0.004
    //         s/op
    // TssBenchmark.p0Signs                             P130S10  SHORT_PUBLIC_KEYS           1024    ss          0.004
    //         s/op
    // TssBenchmark.rekeyObtainPrivateShares             P100S1   SHORT_SIGNATURES            N/A    ss          0.338
    //         s/op
    // TssBenchmark.rekeyObtainPrivateShares             P100S1  SHORT_PUBLIC_KEYS            N/A    ss          0.141
    //         s/op
    // TssBenchmark.rekeyObtainPrivateShares             P100S3   SHORT_SIGNATURES            N/A    ss          3.096
    //         s/op
    // TssBenchmark.rekeyObtainPrivateShares             P100S3  SHORT_PUBLIC_KEYS            N/A    ss          1.283
    //         s/op
    // TssBenchmark.rekeyObtainPrivateShares             P100S5   SHORT_SIGNATURES            N/A    ss          9.226
    //         s/op
    // TssBenchmark.rekeyObtainPrivateShares             P100S5  SHORT_PUBLIC_KEYS            N/A    ss          4.033
    //         s/op
    // TssBenchmark.rekeyObtainPrivateShares            P100S10   SHORT_SIGNATURES            N/A    ss         37.757
    //         s/op
    // TssBenchmark.rekeyObtainPrivateShares            P100S10  SHORT_PUBLIC_KEYS            N/A    ss         18.569
    //         s/op
    // TssBenchmark.rekeyObtainPrivateShares            P130S10   SHORT_SIGNATURES            N/A    ss         52.017
    //         s/op
    // TssBenchmark.rekeyObtainPrivateShares            P130S10  SHORT_PUBLIC_KEYS            N/A    ss         26.669
    //         s/op
    // TssBenchmark.rekeyObtainPublicShares              P100S1   SHORT_SIGNATURES            N/A    ss          4.225
    //         s/op
    // TssBenchmark.rekeyObtainPublicShares              P100S1  SHORT_PUBLIC_KEYS            N/A    ss          3.003
    //         s/op
    // TssBenchmark.rekeyObtainPublicShares              P100S3   SHORT_SIGNATURES            N/A    ss        112.521
    //         s/op
    // TssBenchmark.rekeyObtainPublicShares              P100S3  SHORT_PUBLIC_KEYS            N/A    ss         79.256
    //         s/op
    // TssBenchmark.rekeyObtainPublicShares              P100S5   SHORT_SIGNATURES            N/A    ss        528.783
    //         s/op
    // TssBenchmark.rekeyObtainPublicShares              P100S5  SHORT_PUBLIC_KEYS            N/A    ss        372.264
    //         s/op
    // TssBenchmark.rekeyObtainPublicShares             P100S10   SHORT_SIGNATURES            N/A    ss       4289.557
    //         s/op
    // TssBenchmark.rekeyObtainPublicShares             P100S10  SHORT_PUBLIC_KEYS            N/A    ss       3075.747
    //         s/op
    // TssBenchmark.rekeyObtainPublicShares             P130S10   SHORT_SIGNATURES            N/A    ss       9506.254
    //         s/op
    // TssBenchmark.rekeyObtainPublicShares             P130S10  SHORT_PUBLIC_KEYS            N/A    ss       6631.898
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S1   SHORT_SIGNATURES             32    ss          0.039
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S1   SHORT_SIGNATURES            256    ss          0.037
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S1   SHORT_SIGNATURES           1024    ss          0.036
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S1  SHORT_PUBLIC_KEYS             32    ss          0.046
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S1  SHORT_PUBLIC_KEYS            256    ss          0.045
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S1  SHORT_PUBLIC_KEYS           1024    ss          0.045
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S3   SHORT_SIGNATURES             32    ss          0.249
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S3   SHORT_SIGNATURES            256    ss          0.240
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S3   SHORT_SIGNATURES           1024    ss          0.246
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S3  SHORT_PUBLIC_KEYS             32    ss          0.282
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S3  SHORT_PUBLIC_KEYS            256    ss          0.274
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S3  SHORT_PUBLIC_KEYS           1024    ss          0.281
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S5   SHORT_SIGNATURES             32    ss          0.690
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S5   SHORT_SIGNATURES            256    ss          0.714
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S5   SHORT_SIGNATURES           1024    ss          0.716
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S5  SHORT_PUBLIC_KEYS             32    ss          0.752
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S5  SHORT_PUBLIC_KEYS            256    ss          0.738
    //         s/op
    // TssBenchmark.signatureAggregation                 P100S5  SHORT_PUBLIC_KEYS           1024    ss          0.754
    //         s/op
    // TssBenchmark.signatureAggregation                P100S10   SHORT_SIGNATURES             32    ss          2.617
    //         s/op
    // TssBenchmark.signatureAggregation                P100S10   SHORT_SIGNATURES            256    ss          2.776
    //         s/op
    // TssBenchmark.signatureAggregation                P100S10   SHORT_SIGNATURES           1024    ss          2.713
    //         s/op
    // TssBenchmark.signatureAggregation                P100S10  SHORT_PUBLIC_KEYS             32    ss          2.729
    //         s/op
    // TssBenchmark.signatureAggregation                P100S10  SHORT_PUBLIC_KEYS            256    ss          2.766
    //         s/op
    // TssBenchmark.signatureAggregation                P100S10  SHORT_PUBLIC_KEYS           1024    ss          2.890
    //         s/op
    // TssBenchmark.signatureAggregation                P130S10   SHORT_SIGNATURES             32    ss          4.582
    //         s/op
    // TssBenchmark.signatureAggregation                P130S10   SHORT_SIGNATURES            256    ss          4.233
    //         s/op
    // TssBenchmark.signatureAggregation                P130S10   SHORT_SIGNATURES           1024    ss          4.572
    //         s/op
    // TssBenchmark.signatureAggregation                P130S10  SHORT_PUBLIC_KEYS             32    ss          5.500
    //         s/op
    // TssBenchmark.signatureAggregation                P130S10  SHORT_PUBLIC_KEYS            256    ss          4.570
    //         s/op
    // TssBenchmark.signatureAggregation                P130S10  SHORT_PUBLIC_KEYS           1024    ss          4.912
    //         s/op

    // Benchmark                                (benchmarkTest)  (groupAssignment)  (messageSize)  Mode  Cnt  Score
    // Error  Units
    // TssBenchmark.genesisObtainPrivateShares            P10S3   SHORT_SIGNATURES            N/A    ss       0.321
    //      s/op
    // TssBenchmark.genesisObtainPrivateShares            P10S3  SHORT_PUBLIC_KEYS            N/A    ss       0.124
    //      s/op
    // TssBenchmark.genesisObtainPublicShares             P10S3   SHORT_SIGNATURES            N/A    ss       0.082
    //      s/op
    // TssBenchmark.genesisObtainPublicShares             P10S3  SHORT_PUBLIC_KEYS            N/A    ss       0.059
    //      s/op
    // TssBenchmark.p0Signs                               P10S3   SHORT_SIGNATURES             32    ss       0.001
    //      s/op
    // TssBenchmark.p0Signs                               P10S3   SHORT_SIGNATURES            256    ss       0.001
    //      s/op
    // TssBenchmark.p0Signs                               P10S3   SHORT_SIGNATURES           1024    ss       0.001
    //      s/op
    // TssBenchmark.p0Signs                               P10S3  SHORT_PUBLIC_KEYS             32    ss       0.002
    //      s/op
    // TssBenchmark.p0Signs                               P10S3  SHORT_PUBLIC_KEYS            256    ss       0.002
    //      s/op
    // TssBenchmark.p0Signs                               P10S3  SHORT_PUBLIC_KEYS           1024    ss       0.002
    //      s/op
    // TssBenchmark.rekeyObtainPrivateShares              P10S3   SHORT_SIGNATURES            N/A    ss       0.326
    //      s/op
    // TssBenchmark.rekeyObtainPrivateShares              P10S3  SHORT_PUBLIC_KEYS            N/A    ss       0.130
    //      s/op
    // TssBenchmark.rekeyObtainPublicShares               P10S3   SHORT_SIGNATURES            N/A    ss       0.149
    //      s/op
    // TssBenchmark.rekeyObtainPublicShares               P10S3  SHORT_PUBLIC_KEYS            N/A    ss       0.102
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3   SHORT_SIGNATURES             32    ss       0.007
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3   SHORT_SIGNATURES            256    ss       0.007
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3   SHORT_SIGNATURES           1024    ss       0.007
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3  SHORT_PUBLIC_KEYS             32    ss       0.008
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3  SHORT_PUBLIC_KEYS            256    ss       0.008
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3  SHORT_PUBLIC_KEYS           1024    ss       0.008
    //      s/op

    // non check
    // Benchmark                                (benchmarkTest)  (groupAssignment)  (messageSize)  Mode  Cnt  Score
    // Error  Units
    // TssBenchmark.genesisObtainPrivateShares            P10S3   SHORT_SIGNATURES            N/A    ss       0.327
    //      s/op
    // TssBenchmark.genesisObtainPrivateShares            P10S3  SHORT_PUBLIC_KEYS            N/A    ss       0.126
    //      s/op
    // TssBenchmark.genesisObtainPublicShares             P10S3   SHORT_SIGNATURES            N/A    ss       0.081
    //      s/op
    // TssBenchmark.genesisObtainPublicShares             P10S3  SHORT_PUBLIC_KEYS            N/A    ss       0.062
    //      s/op
    // TssBenchmark.p0Signs                               P10S3   SHORT_SIGNATURES             32    ss       0.001
    //      s/op
    // TssBenchmark.p0Signs                               P10S3   SHORT_SIGNATURES            256    ss       0.001
    //      s/op
    // TssBenchmark.p0Signs                               P10S3   SHORT_SIGNATURES           1024    ss       0.001
    //      s/op
    // TssBenchmark.p0Signs                               P10S3  SHORT_PUBLIC_KEYS             32    ss       0.002
    //      s/op
    // TssBenchmark.p0Signs                               P10S3  SHORT_PUBLIC_KEYS            256    ss       0.002
    //      s/op
    // TssBenchmark.p0Signs                               P10S3  SHORT_PUBLIC_KEYS           1024    ss       0.002
    //      s/op
    // TssBenchmark.rekeyObtainPrivateShares              P10S3   SHORT_SIGNATURES            N/A    ss       0.309
    //      s/op
    // TssBenchmark.rekeyObtainPrivateShares              P10S3  SHORT_PUBLIC_KEYS            N/A    ss       0.129
    //      s/op
    // TssBenchmark.rekeyObtainPublicShares               P10S3   SHORT_SIGNATURES            N/A    ss       0.149
    //      s/op
    // TssBenchmark.rekeyObtainPublicShares               P10S3  SHORT_PUBLIC_KEYS            N/A    ss       0.102
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3   SHORT_SIGNATURES             32    ss       0.007
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3   SHORT_SIGNATURES            256    ss       0.007
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3   SHORT_SIGNATURES           1024    ss       0.007
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3  SHORT_PUBLIC_KEYS             32    ss       0.009
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3  SHORT_PUBLIC_KEYS            256    ss       0.009
    //      s/op
    // TssBenchmark.signatureAggregation                  P10S3  SHORT_PUBLIC_KEYS           1024    ss       0.008
    //      s/op
    @Benchmark
    public List<?> genesisObtainPublicShares(TssGenesisState state) {
        return state.genesisExtractor.allPublicShares();
    }

    @Benchmark
    public List<?> genesisObtainPrivateShares(TssGenesisState state) {
        return state.genesisExtractor.ownedPrivateShares(state.privateInfo);
    }

    @Benchmark
    public List<?> rekeyObtainPrivateShares(TssRekeyState state) {
        return state.rekeyExtractor.ownedPrivateShares(state.privateInfo);
    }

    @Benchmark
    public List<?> p0Signs(TssSignatureState state) {
        return state.privateShares.getFirst().stream()
                .map(s -> s.sign(state.message))
                .toList();
    }

    @Benchmark
    public BlsSignature signatureAggregation(TssSignatureState state) {
        return TssShareSignature.aggregate(state.allSignatures);
    }

    @Benchmark
    public List<?> rekeyObtainPublicShares(TssRekeyState state) {
        return state.rekeyExtractor.allPublicShares();
    }

    @State(Scope.Benchmark)
    public static class TssGenesisState {
        TssShareExtractor genesisExtractor;
        TssParticipantPrivateInfo privateInfo;

        @Setup
        public void init() {

            System.out.printf("%n%d:init started%n", System.currentTimeMillis());
            TssService tssService = new Groth21Service(signatureSchema, rng);
            final BlsPrivateKey[] keys = TssTestUtils.rndSks(
                    signatureSchema,
                    rng,
                    parseBenchmarkTestString(benchmarkTest).participants());

            var genesisCommittee = from(benchmarkTest, keys);
            var setupMessages = TssTestUtils.simulateGenesisMessaging(tssService, genesisCommittee);
            privateInfo = genesisCommittee.privateInfoOf(0);
            genesisExtractor =
                    tssService.genesisStage().shareExtractor(genesisCommittee.participantDirectory(), setupMessages);
            System.out.printf("%n%d:init finished%n", System.currentTimeMillis());
        }
    }

    @State(Scope.Benchmark)
    public static class TssRekeyState {
        TssShareExtractor rekeyExtractor;
        TssParticipantPrivateInfo privateInfo;

        @Setup
        public void init() {
            System.out.printf("%n%d:init started%n", System.currentTimeMillis());

            TssService tssService = new Groth21Service(signatureSchema, rng);
            final BlsPrivateKey[] keys = TssTestUtils.rndSks(
                    signatureSchema,
                    rng,
                    parseBenchmarkTestString(benchmarkTest).participants());
            var privateSharesPerParticipant =
                    TssTestUtils.randomPrivateShares(from(benchmarkTest, keys), rng, signatureSchema);
            var targetCommittee = from(benchmarkTest, keys);
            System.out.printf("%n%d:init rekey%n", System.currentTimeMillis());
            var rekeyMessages =
                    TssTestUtils.simulateRekeyMessaging(tssService, targetCommittee, privateSharesPerParticipant);
            rekeyExtractor =
                    tssService.rekeyStage().shareExtractor(targetCommittee.participantDirectory(), rekeyMessages);
            privateInfo = targetCommittee.privateInfoOf(0);
            System.out.printf("%n%d:init finished%n", System.currentTimeMillis());
        }
    }

    @State(Scope.Benchmark)
    public static class TssSignatureState {
        byte[] message;
        List<TssShareSignature> signatures;

        @Param({"32", "256", "1024"})
        public int messageSize;

        BlsPublicKey ledgerId;
        List<TssShareSignature> allSignatures;
        List<List<TssPrivateShare>> privateShares;

        @Setup
        public void init() {
            this.message = new byte[messageSize];
            rng.nextBytes(message);
            final BlsPrivateKey[] keys = TssTestUtils.rndSks(
                    signatureSchema,
                    rng,
                    parseBenchmarkTestString(benchmarkTest).participants());
            this.privateShares = TssTestUtils.randomPrivateShares(from(benchmarkTest, keys), rng, signatureSchema);
            var publicShares = privateShares.stream()
                    .map(l -> l.stream()
                            .map(sk -> new TssPublicShare(
                                    sk.shareId(), sk.privateKey().createPublicKey()))
                            .toList())
                    .toList();
            var allPublicShares =
                    publicShares.stream().flatMap(Collection::stream).toList();
            this.ledgerId = TssPublicShare.aggregate(allPublicShares);
            this.allSignatures = privateShares.stream()
                    .flatMap(l -> l.stream().map(s -> s.sign(message)))
                    .toList();
        }
    }

    /**
     * Parses a string in the format "PXSY" and extracts the integers X and Y.
     *
     * @param input The input string in the format "PXSY" (e.g., "P100S10").
     * @return An array of two integers where the first element is X and the second is Y.
     * @throws IllegalArgumentException If the input string is not in the expected format.
     */
    public static BenchmarkTest parseBenchmarkTestString(final String input) {
        // Define the regular expression pattern for "PXSY"
        Pattern pattern = Pattern.compile("^P(\\d+)S(\\d+)$");
        Matcher matcher = pattern.matcher(input);

        // If the pattern matches, extract the integers
        if (matcher.matches()) {
            int x = Integer.parseInt(matcher.group(1)); // Extract X
            int y = Integer.parseInt(matcher.group(2)); // Extract Y
            return new BenchmarkTest(x, y);
        } else {
            // Throw an exception if the input is not valid
            throw new IllegalArgumentException("Invalid input format. Expected format: PXSY (e.g., P100S10)");
        }
    }

    public record BenchmarkTest(int participants, int shares) {}

    static TssTestCommittee from(String param, BlsPrivateKey... keys) {
        var test = parseBenchmarkTestString(param);
        return new TssTestCommittee(test.participants(), test.shares(), keys);
    }
}
