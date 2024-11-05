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

package com.hedera.cryptography.bls;

import com.hedera.cryptography.bls.test.fixtures.BlsTestUtils;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.utils.test.fixtures.rng.SeededRandom;
import java.util.List;
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
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

@State(Scope.Benchmark)
@Fork(value = 1)
@Warmup(iterations = 1, time = 5)
@Measurement(iterations = 2, time = 10)
public class SignatureAggregationBenchmarks {
    public static final int MESSAGE_SIZE = 1024;

    @Param({"32", "256", "1024"})
    public int numSignatures;

    @Param({"SHORT_SIGNATURES", "SHORT_PUBLIC_KEYS"})
    public GroupAssignment groupAssignment;

    private List<BlsSignature> signatures;

    @Setup
    public void setup() {
        final SeededRandom random = new SeededRandom();
        final List<BlsKeyPair> keyPairs = BlsTestUtils.generateKeyPairs(
                random, SignatureSchema.create(Curve.ALT_BN128, groupAssignment), numSignatures);
        signatures = BlsTestUtils.bulkSign(keyPairs, random.randomBytes(MESSAGE_SIZE));
    }
    /*
    Results on M1 Max MacBook Pro:

    Benchmark                                 (groupAssignment)  (numSignatures)  Mode  Cnt  Score   Error  Units
    SignatureAggregationBenchmarks.aggregate   SHORT_SIGNATURES               32  avgt    2  0.024          ms/op
    SignatureAggregationBenchmarks.aggregate   SHORT_SIGNATURES              256  avgt    2  0.172          ms/op
    SignatureAggregationBenchmarks.aggregate   SHORT_SIGNATURES             1024  avgt    2  0.703          ms/op
    SignatureAggregationBenchmarks.aggregate  SHORT_PUBLIC_KEYS               32  avgt    2  0.043          ms/op
    SignatureAggregationBenchmarks.aggregate  SHORT_PUBLIC_KEYS              256  avgt    2  0.336          ms/op
    SignatureAggregationBenchmarks.aggregate  SHORT_PUBLIC_KEYS             1024  avgt    2  1.414          ms/op
    */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void aggregate(final Blackhole bh) {
        bh.consume(BlsSignature.aggregate(signatures));
    }
}
