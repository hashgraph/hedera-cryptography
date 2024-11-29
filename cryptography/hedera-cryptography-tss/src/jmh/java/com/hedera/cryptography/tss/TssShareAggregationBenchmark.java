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
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
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

@State(Scope.Benchmark)
@Threads(10)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 1)
@Measurement(iterations = 2)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class TssShareAggregationBenchmark {
    @Param({"SHORT_PUBLIC_KEYS", "SHORT_SIGNATURES"})
    GroupAssignment assignment;

    @Param({"10", "20", "30", "50", "100", "1000", "2000"})
    int size;

    Field field;
    List<TssPublicShare> publicShares;
    List<TssPrivateShare> privateShares;
    // *****************************************************
    // Pre optimize
    // Benchmark                                                   (assignment)  (size)  Mode  Cnt      Score   Error
    // Units
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS      10  avgt    2      0.280
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS      20  avgt    2      1.077
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS      30  avgt    2      2.170
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS      50  avgt    2      6.401
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS     100  avgt    2     24.819
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS    1000  avgt    2   2746.202
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS    2000  avgt    2   9090.956
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES      10  avgt    2      0.282
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES      20  avgt    2      1.087
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES      30  avgt    2      2.288
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES      50  avgt    2      6.627
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES     100  avgt    2     24.006
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES    1000  avgt    2   2571.725
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES    2000  avgt    2  10914.917
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS      10  avgt    2      0.677
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS      20  avgt    2      1.809
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS      30  avgt    2      3.480
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS      50  avgt    2      8.622
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS     100  avgt    2     31.082
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS    1000  avgt    2   2994.733
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS    2000  avgt    2  10913.157
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES      10  avgt    2      1.487
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES      20  avgt    2      3.651
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES      30  avgt    2      6.453
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES      50  avgt    2     13.671
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES     100  avgt    2     40.352
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES    1000  avgt    2   2578.196
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES    2000  avgt    2  10475.840
    // ms/op

    // *****************************************************
    // Post optimize
    // Benchmark                                                   (assignment)  (size)  Mode  Cnt    Score   Error
    // Units
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS      10  avgt    2    0.051
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS      20  avgt    2    0.112
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS      30  avgt    2    0.196
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS      50  avgt    2    0.373
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS     100  avgt    2    1.114
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS    1000  avgt    2   73.335
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate  SHORT_PUBLIC_KEYS    2000  avgt    2  292.398
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES      10  avgt    2    0.052
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES      20  avgt    2    0.116
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES      30  avgt    2    0.198
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES      50  avgt    2    0.379
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES     100  avgt    2    1.097
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES    1000  avgt    2   73.317
    // ms/op
    // TssShareAggregationBenchmark.TssPrivateShareAggregate   SHORT_SIGNATURES    2000  avgt    2  279.626
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS      10  avgt    2    0.332
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS      20  avgt    2    0.680
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS      30  avgt    2    1.065
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS      50  avgt    2    2.023
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS     100  avgt    2    5.300
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS    1000  avgt    2  144.866
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate   SHORT_PUBLIC_KEYS    2000  avgt    2  427.335
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES      10  avgt    2    0.847
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES      20  avgt    2    1.893
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES      30  avgt    2    3.023
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES      50  avgt    2    5.486
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES     100  avgt    2   13.138
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES    1000  avgt    2  268.121
    // ms/op
    // TssShareAggregationBenchmark.TssPublicShareAggregate    SHORT_SIGNATURES    2000  avgt    2  676.182
    // ms/op

    @Setup
    public void setup() {
        Random random = new Random();
        var schema = SignatureSchema.create(Curve.ALT_BN128, assignment);
        field = schema.getPairingFriendlyCurve().field();
        privateShares = IntStream.rangeClosed(1, size)
                .mapToObj(i -> new TssPrivateShare(i, BlsPrivateKey.create(schema, random)))
                .toList();
        publicShares = privateShares.stream()
                .map(ps -> new TssPublicShare(ps.shareId(), ps.privateKey().createPublicKey()))
                .toList();
    }

    @Benchmark
    public BlsPrivateKey TssPrivateShareAggregate() {

        return TssPrivateShare.aggregate(privateShares);
    }

    @Benchmark
    public BlsPublicKey TssPublicShareAggregate() {

        return TssPublicShare.aggregate(publicShares);
    }
}
