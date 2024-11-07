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

import com.hedera.cryptography.pairings.api.FieldElement;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

@State(Scope.Benchmark)
public class FieldElementEqualityAndHashCodeBenchmark {
    FieldElement a;
    FieldElement b;

    // Benchmark using arkworks equals              Mode  Cnt     Score   Error   Units
    // EqualityAndHashCodeBenchmark.benchEquals     thrpt    2  2817.190          ops/ms
    // EqualityAndHashCodeBenchmark.benchHashCode   thrpt    2  3939.389          ops/ms
    // EqualityAndHashCodeBenchmark.benchNotEquals  thrpt    2  2735.414          ops/ms

    // Benchmark using java array equals         Mode  Cnt     Score   Error   Units
    // EqualityAndHashCodeBenchmark.benchEquals     thrpt    2  37919.827          ops/ms
    // EqualityAndHashCodeBenchmark.benchHashCode   thrpt    2   3256.847          ops/ms
    // EqualityAndHashCodeBenchmark.benchNotEquals  thrpt    2  44346.141          ops/ms

    @Setup(Level.Trial)
    public void init() {
        var seed = new Random().nextLong();
        System.out.println("Random Seed: " + seed);
        var rng = new Random(seed);
        var field = new AltBn128Field();
        var aVal = rng.nextLong();
        var bVal = aVal;
        do {
            bVal = rng.nextLong();
        } while (bVal == aVal);
        a = field.fromLong(rng.nextLong());
        b = field.fromLong(rng.nextLong());
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
