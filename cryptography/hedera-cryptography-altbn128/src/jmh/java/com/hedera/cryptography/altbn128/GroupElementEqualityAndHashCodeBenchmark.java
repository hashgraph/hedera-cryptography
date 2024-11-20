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

package com.hedera.cryptography.altbn128;

import com.hedera.cryptography.pairings.api.GroupElement;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

@State(Scope.Benchmark)
public class GroupElementEqualityAndHashCodeBenchmark {
    GroupElement a;
    GroupElement b;

    // Benchmark using arkworks equals
    // Benchmark                                                (value)   Mode  Cnt      Score   Error   Units
    // GroupElementEqualityAndHashCodeBenchmark.benchEquals      GROUP1  thrpt    2  42585.582          ops/ms
    // GroupElementEqualityAndHashCodeBenchmark.benchEquals      GROUP2  thrpt    2  24410.637          ops/ms
    // GroupElementEqualityAndHashCodeBenchmark.benchHashCode    GROUP1  thrpt    2   2905.944          ops/ms
    // GroupElementEqualityAndHashCodeBenchmark.benchHashCode    GROUP2  thrpt    2   2320.878          ops/ms
    // GroupElementEqualityAndHashCodeBenchmark.benchNotEquals   GROUP1  thrpt    2   2989.959          ops/ms
    // GroupElementEqualityAndHashCodeBenchmark.benchNotEquals   GROUP2  thrpt    2   1959.134          ops/ms

    // Benchmark using Java equals
    // Benchmark                                                (value)   Mode  Cnt      Score   Error   Units
    // GroupElementEqualityAndHashCodeBenchmark.benchEquals      GROUP1  thrpt    2  55697.286          ops/ms
    // GroupElementEqualityAndHashCodeBenchmark.benchEquals      GROUP2  thrpt    2  57294.366          ops/ms
    // GroupElementEqualityAndHashCodeBenchmark.benchHashCode    GROUP1  thrpt    2   2897.270          ops/ms
    // GroupElementEqualityAndHashCodeBenchmark.benchHashCode    GROUP2  thrpt    2   1919.371          ops/ms
    // GroupElementEqualityAndHashCodeBenchmark.benchNotEquals   GROUP1  thrpt    2  42381.367          ops/ms
    // GroupElementEqualityAndHashCodeBenchmark.benchNotEquals   GROUP2  thrpt    2  45499.379          ops/ms

    @Param({"GROUP1", "GROUP2"})
    String value;

    @Setup(Level.Trial)
    public void init() {
        var seed = new Random().nextLong();
        var field = new AltBn128Field();
        System.out.println("Random Seed: " + seed);
        var rng = new Random(seed);
        var group = new AltBn128Group(AltBN128CurveGroup.valueOf(value), field);

        var aVal = new byte[group.seedSize()];
        var bVal = new byte[group.seedSize()];
        rng.nextBytes(aVal);
        do {
            rng.nextBytes(bVal);
        } while (Arrays.equals(aVal, bVal));

        a = group.random(aVal);
        b = group.random(bVal);
    }

    @Benchmark
    @Fork(value = 2)
    @Threads(2)
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    public void benchNotEquals(Blackhole blackhole) {
        blackhole.consume(a.equals(b));
    }

    @Benchmark
    @Fork(value = 2)
    @Threads(2)
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    @SuppressWarnings("EqualsWithItself")
    public void benchEquals(Blackhole blackhole) {
        blackhole.consume(a.equals(a));
    }

    @Benchmark
    @Fork(value = 2)
    @Threads(2)
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    public void benchHashCode(Blackhole blackhole) {
        blackhole.consume(a.hashCode());
    }
}
