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

    @Param({"-1", "0", "1"})
    public int randomSeed;

    @Param({"32", "256", "1024"})
    public int numSignatures;

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

Benchmark              (groupAssignment)  (messageSize)  (numSignatures)  (randomSeed)   Mode  Cnt      Score   Error  Units
SigningBenchmark.sign   SHORT_SIGNATURES             32               32            -1  thrpt    2  11166.299          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES             32               32             0  thrpt    2  10801.528          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES             32               32             1  thrpt    2  10846.852          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES             32              256            -1  thrpt    2  10928.348          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES             32              256             0  thrpt    2  10824.737          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES             32              256             1  thrpt    2  11004.491          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES             32             1024            -1  thrpt    2  10651.376          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES             32             1024             0  thrpt    2  10995.799          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES             32             1024             1  thrpt    2  11043.231          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES           1024               32            -1  thrpt    2  10757.248          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES           1024               32             0  thrpt    2  11725.378          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES           1024               32             1  thrpt    2  11738.462          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES           1024              256            -1  thrpt    2  10950.515          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES           1024              256             0  thrpt    2  11827.454          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES           1024              256             1  thrpt    2  11936.017          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES           1024             1024            -1  thrpt    2  10955.297          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES           1024             1024             0  thrpt    2  11791.377          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES           1024             1024             1  thrpt    2  11929.633          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES          16384               32            -1  thrpt    2   8413.714          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES          16384               32             0  thrpt    2   7827.172          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES          16384               32             1  thrpt    2   8860.038          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES          16384              256            -1  thrpt    2   8400.454          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES          16384              256             0  thrpt    2   7754.323          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES          16384              256             1  thrpt    2   8900.231          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES          16384             1024            -1  thrpt    2   8402.799          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES          16384             1024             0  thrpt    2   7634.318          ops/s
SigningBenchmark.sign   SHORT_SIGNATURES          16384             1024             1  thrpt    2   8866.074          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32               32            -1  thrpt    2   2148.329          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32               32             0  thrpt    2   2095.291          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32               32             1  thrpt    2   2197.261          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32              256            -1  thrpt    2   2189.478          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32              256             0  thrpt    2   2142.401          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32              256             1  thrpt    2   2181.239          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32             1024            -1  thrpt    2   2162.919          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32             1024             0  thrpt    2   2105.050          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS             32             1024             1  thrpt    2   2163.465          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024               32            -1  thrpt    2   2174.879          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024               32             0  thrpt    2   2158.156          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024               32             1  thrpt    2   2146.812          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024              256            -1  thrpt    2   2165.618          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024              256             0  thrpt    2   2138.571          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024              256             1  thrpt    2   2165.079          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024             1024            -1  thrpt    2   2182.321          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024             1024             0  thrpt    2   2154.209          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS           1024             1024             1  thrpt    2   2156.712          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384               32            -1  thrpt    2   2019.860          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384               32             0  thrpt    2   1940.249          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384               32             1  thrpt    2   1895.564          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384              256            -1  thrpt    2   1987.619          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384              256             0  thrpt    2   1945.064          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384              256             1  thrpt    2   2072.364          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384             1024            -1  thrpt    2   1876.663          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384             1024             0  thrpt    2   1990.017          ops/s
SigningBenchmark.sign  SHORT_PUBLIC_KEYS          16384             1024             1  thrpt    2   2068.259          ops/s
*/
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public void sign(final Blackhole bh) {
        bh.consume(keyPair.privateKey().sign(message));
    }
}
