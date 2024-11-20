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
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.tss.extensions.Lagrange;
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
public class LagrangeBenchmark {
    // Benchmark                                      (assignment)  (size)  Mode  Cnt      Score   Error  Units
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS      10  avgt    2      0.252          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS      20  avgt    2      1.168          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS      30  avgt    2      2.504          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS      50  avgt    2      7.664          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS     100  avgt    2     28.367          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS    1000  avgt    2   2513.435          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS    2000  avgt    2   9856.288          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES      10  avgt    2      0.288          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES      20  avgt    2      1.035          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES      30  avgt    2      2.396          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES      50  avgt    2      6.345          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES     100  avgt    2     27.334          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES    1000  avgt    2   2792.709          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES    2000  avgt    2  10965.386          ms/op

    // Benchmark                                      (assignment)  (size)  Mode  Cnt    Score   Error  Units
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS      10  avgt    2    0.331          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS      20  avgt    2    0.680          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS      30  avgt    2    1.072          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS      50  avgt    2    2.026          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS     100  avgt    2    5.280          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS    1000  avgt    2  146.289          ms/op
    // LagrangeBenchmark.aggregateGroupElements  SHORT_PUBLIC_KEYS    2000  avgt    2  425.131          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES      10  avgt    2    0.833          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES      20  avgt    2    1.820          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES      30  avgt    2    2.964          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES      50  avgt    2    5.447          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES     100  avgt    2   13.078          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES    1000  avgt    2  267.607          ms/op
    // LagrangeBenchmark.aggregateGroupElements   SHORT_SIGNATURES    2000  avgt    2  676.707          ms/op
    @Param({"SHORT_PUBLIC_KEYS", "SHORT_SIGNATURES"})
    GroupAssignment assignment;

    @Param({"10", "20", "30", "50", "100", "1000", "2000"})
    int size;

    List<Integer> xs;
    List<GroupElement> ys;

    @Setup
    public void setup() {
        Random random = new Random();
        var schema = SignatureSchema.create(Curve.ALT_BN128, assignment);
        var group = schema.getPublicKeyGroup();
        xs = IntStream.rangeClosed(1, size).boxed().toList();
        ys = IntStream.range(0, size).boxed().map(i -> group.random(random)).toList();
    }

    @Benchmark
    public GroupElement aggregateGroupElements() {
        return Lagrange.recoverGroupElement(xs, ys);
    }
}
