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
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

@State(Scope.Benchmark)
@Fork(value = 1)
@Warmup(iterations = 1, time = 1)
@Measurement(iterations = 2, time = 5)
public class SigningBenchmark {

    @Param({"32", "1024", "16384"})
    public int messageSize;

    @Param({"0", "10000000"})
    public int randomSeed;

    @Param({"SHORT_SIGNATURES", "SHORT_PUBLIC_KEYS"})
    public GroupAssignment groupAssignment;

    private BlsKeyPair keyPair;
    private byte[] message;

    @Setup
    public void setup() {
        final Random random = new Random(randomSeed);
        keyPair = BlsKeyPair.generate(SignatureSchema.create(Curve.ALT_BN128, groupAssignment), random);
        message = BlsTestUtils.randomBytes(randomSeed, messageSize);
    }
/*
Results on M1 Max MacBook Pro:

Benchmark              (groupAssignment)  (messageSize)  (randomSeed)  Mode  Cnt  Score   Error  Units
SigningBenchmark.sign   SHORT_SIGNATURES             32             0  avgt    2  0.090          ms/op
SigningBenchmark.sign   SHORT_SIGNATURES             32      10000000  avgt    2  0.096          ms/op
SigningBenchmark.sign   SHORT_SIGNATURES           1024             0  avgt    2  0.085          ms/op
SigningBenchmark.sign   SHORT_SIGNATURES           1024      10000000  avgt    2  0.091          ms/op
SigningBenchmark.sign   SHORT_SIGNATURES          16384             0  avgt    2  0.127          ms/op
SigningBenchmark.sign   SHORT_SIGNATURES          16384      10000000  avgt    2  0.110          ms/op
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32             0  avgt    2  0.463          ms/op
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32      10000000  avgt    2  0.465          ms/op
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024             0  avgt    2  0.459          ms/op
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024      10000000  avgt    2  0.451          ms/op
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384             0  avgt    2  0.502          ms/op
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384      10000000  avgt    2  0.487          ms/op
*/
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void sign(final Blackhole bh) {
        bh.consume(keyPair.privateKey().sign(message));
    }
}
