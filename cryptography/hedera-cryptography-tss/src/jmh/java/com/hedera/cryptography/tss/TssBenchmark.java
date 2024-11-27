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
import com.hedera.cryptography.tss.api.TssParticipantPrivateInfo;
import com.hedera.cryptography.tss.api.TssShareExtractor;
import com.hedera.cryptography.tss.extensions.Groth21Service;
import com.hedera.cryptography.tss.test.fixtures.TssTestCommittee;
import com.hedera.cryptography.tss.test.fixtures.TssTestUtils;
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
@Threads(1)
@Warmup(iterations = 0)
@Measurement(iterations = 1)
@BenchmarkMode(Mode.SingleShotTime)
@OutputTimeUnit(TimeUnit.SECONDS)
public class TssBenchmark {

    @Param({"130"})
    static int participants;

    @Param({"10"})
    static int shares;

    @Param({"SHORT_SIGNATURES", "SHORT_PUBLIC_KEYS"})
    static GroupAssignment groupAssignment;

    // Benchmark (pre multi-arity) s/op          (benchmarkTest)  (groupAssignment)  Mode  Cnt     ΩScore
    // TssBenchmark.genesisObtainPrivateShares          P130S10  SHORT_PUBLIC_KEYS     ss         16.104
    // TssBenchmark.genesisObtainPublicShares           P130S10  SHORT_PUBLIC_KEYS     ss       5226.440
    // TssBenchmark.rekeyObtainPrivateShares            P130S10  SHORT_PUBLIC_KEYS     ss         26.669
    // TssBenchmark.rekeyObtainPublicShares             P130S10  SHORT_PUBLIC_KEYS     ss       6631.898

    // TssBenchmark.genesisObtainPrivateShares          P130S10   SHORT_SIGNATURES     ss         42.122
    // TssBenchmark.genesisObtainPublicShares           P130S10   SHORT_SIGNATURES     ss       8109.137
    // TssBenchmark.rekeyObtainPrivateShares            P130S10   SHORT_SIGNATURES     ss         52.017
    // TssBenchmark.rekeyObtainPublicShares             P130S10   SHORT_SIGNATURES     ss       9506.254

    // Benchmark (post multi-arity) s/op         (benchmarkTest)  (groupAssignment)  Mode  Cnt     Score
    // TssBenchmark.genesisObtainPrivateShares          P130S10  SHORT_PUBLIC_KEYS    ss         16.382
    // TssBenchmark.genesisObtainPublicShares           P130S10  SHORT_PUBLIC_KEYS    ss       5175.349
    // TssBenchmark.rekeyObtainPrivateShares            P130S10  SHORT_PUBLIC_KEYS    ss         17.666
    // TssBenchmark.rekeyObtainPublicShares             P130S10  SHORT_PUBLIC_KEYS    ss       5380.933

    // TssBenchmark.genesisObtainPrivateShares          P130S10   SHORT_SIGNATURES    ss         41.072
    // TssBenchmark.genesisObtainPublicShares           P130S10   SHORT_SIGNATURES    ss       7737.224
    // TssBenchmark.rekeyObtainPrivateShares            P130S10   SHORT_SIGNATURES    ss         41.909
    // TssBenchmark.rekeyObtainPublicShares             P130S10   SHORT_SIGNATURES    ss       7899.001

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
            var rng = new Random();
            var signatureSchema = SignatureSchema.create(Curve.ALT_BN128, groupAssignment);
            var tssService = new Groth21Service(signatureSchema, rng);
            var keys = TssTestUtils.rndSks(signatureSchema, rng, participants);

            var genesisCommittee = new TssTestCommittee(participants, shares, keys);
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
            var rng = new Random();
            var signatureSchema = SignatureSchema.create(Curve.ALT_BN128, groupAssignment);
            var tssService = new Groth21Service(signatureSchema, rng);
            var keys = TssTestUtils.rndSks(signatureSchema, rng, participants);
            var targetCommittee = new TssTestCommittee(participants, shares, keys);
            var privateSharesPerParticipant = TssTestUtils.randomPrivateShares(targetCommittee, rng, signatureSchema);
            System.out.printf("%n%d:init rekey%n", System.currentTimeMillis());
            var rekeyMessages =
                    TssTestUtils.simulateRekeyMessaging(tssService, targetCommittee, privateSharesPerParticipant);
            rekeyExtractor =
                    tssService.rekeyStage().shareExtractor(targetCommittee.participantDirectory(), rekeyMessages);
            privateInfo = targetCommittee.privateInfoOf(0);
            System.out.printf("%n%d:init finished%n", System.currentTimeMillis());
        }
    }
}
