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
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.extensions.EcPolynomial;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
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

@State(Scope.Benchmark)
public class GroupElementMbcVsHorner {
    AltBn128Group group;
    EcPolynomial polynomial;

    // This benchmark compares different ways of evaluating a polynomial when the input fits an integer
    // It seems horner's evaluation method still beats the other options.

    // Benchmark                                        (degree)  (value)  Mode  Cnt    Score   Error  Units
    // GroupElementMbcVsHorner.hornersWithFieldElement        10   GROUP1    ss    2    0.199          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement        10   GROUP2    ss    2    0.295          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement        20   GROUP1    ss    2    0.336          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement        20   GROUP2    ss    2    0.718          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement        50   GROUP1    ss    2    0.883          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement        50   GROUP2    ss    2    1.711          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement       128   GROUP1    ss    2    1.991          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement       128   GROUP2    ss    2    4.155          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement       256   GROUP1    ss    2    3.797          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement       256   GROUP2    ss    2    7.386          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement       512   GROUP1    ss    2    7.948          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement       512   GROUP2    ss    2   16.626          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement      1024   GROUP1    ss    2   16.819          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement      1024   GROUP2    ss    2   31.148          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement      2048   GROUP1    ss    2   31.502          ms/op
    // GroupElementMbcVsHorner.hornersWithFieldElement      2048   GROUP2    ss    2   65.378          ms/op
    // GroupElementMbcVsHorner.hornersWithLong                10   GROUP1    ss    2    0.163          ms/op
    // GroupElementMbcVsHorner.hornersWithLong                10   GROUP2    ss    2    0.316          ms/op
    // GroupElementMbcVsHorner.hornersWithLong                20   GROUP1    ss    2    0.345          ms/op
    // GroupElementMbcVsHorner.hornersWithLong                20   GROUP2    ss    2    0.614          ms/op
    // GroupElementMbcVsHorner.hornersWithLong                50   GROUP1    ss    2    0.783          ms/op
    // GroupElementMbcVsHorner.hornersWithLong                50   GROUP2    ss    2    1.418          ms/op
    // GroupElementMbcVsHorner.hornersWithLong               128   GROUP1    ss    2    2.090          ms/op
    // GroupElementMbcVsHorner.hornersWithLong               128   GROUP2    ss    2    4.212          ms/op
    // GroupElementMbcVsHorner.hornersWithLong               256   GROUP1    ss    2    3.884          ms/op
    // GroupElementMbcVsHorner.hornersWithLong               256   GROUP2    ss    2    8.380          ms/op
    // GroupElementMbcVsHorner.hornersWithLong               512   GROUP1    ss    2    7.734          ms/op
    // GroupElementMbcVsHorner.hornersWithLong               512   GROUP2    ss    2   15.962          ms/op
    // GroupElementMbcVsHorner.hornersWithLong              1024   GROUP1    ss    2   14.634          ms/op
    // GroupElementMbcVsHorner.hornersWithLong              1024   GROUP2    ss    2   31.487          ms/op
    // GroupElementMbcVsHorner.hornersWithLong              2048   GROUP1    ss    2   30.242          ms/op
    // GroupElementMbcVsHorner.hornersWithLong              2048   GROUP2    ss    2   60.887          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement            10   GROUP1    ss    2    0.421          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement            10   GROUP2    ss    2    1.178          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement            20   GROUP1    ss    2    1.135          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement            20   GROUP2    ss    2    3.044          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement            50   GROUP1    ss    2    3.239          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement            50   GROUP2    ss    2    8.966          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement           128   GROUP1    ss    2    8.791          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement           128   GROUP2    ss    2   24.016          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement           256   GROUP1    ss    2   18.125          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement           256   GROUP2    ss    2   49.220          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement           512   GROUP1    ss    2   36.205          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement           512   GROUP2    ss    2   98.250          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement          1024   GROUP1    ss    2   73.131          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement          1024   GROUP2    ss    2  199.248          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement          2048   GROUP1    ss    2  145.505          ms/op
    // GroupElementMbcVsHorner.mbcWithFieldElement          2048   GROUP2    ss    2  397.363          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                    10   GROUP1    ss    2    0.308          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                    10   GROUP2    ss    2    0.919          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                    20   GROUP1    ss    2    0.714          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                    20   GROUP2    ss    2    2.050          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                    50   GROUP1    ss    2    2.064          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                    50   GROUP2    ss    2    4.418          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                   128   GROUP1    ss    2    2.529          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                   128   GROUP2    ss    2   13.736          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                   256   GROUP1    ss    2    5.696          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                   256   GROUP2    ss    2   15.548          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                   512   GROUP1    ss    2    2.170          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                   512   GROUP2    ss    2   57.675          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                  1024   GROUP1    ss    2    3.047          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                  1024   GROUP2    ss    2  116.130          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                  2048   GROUP1    ss    2   85.047          ms/op
    // GroupElementMbcVsHorner.mbcWithLong                  2048   GROUP2    ss    2  229.418          ms/op

    @Param({"10", "20", "50", "128", "256", "512", "1024", "2048"})
    int degree;

    @Param({"GROUP1", "GROUP2"})
    String value;

    List<GroupElement> coeffPoitns;
    int xInt;

    @Setup(Level.Trial)
    public void init() {
        var rng = new Random();
        var field = new AltBn128Field();
        group = new AltBn128Group(AltBN128CurveGroup.valueOf(value), field);
        var coeffFields =
                IntStream.range(0, degree).mapToObj(i -> field.random(rng)).toList();
        coeffPoitns =
                coeffFields.stream().map(fe -> group.generator().multiply(fe)).toList();
        polynomial = new EcPolynomial(coeffPoitns);
        xInt = rng.nextInt(0, Integer.MAX_VALUE);
    }

    @Benchmark
    @Fork(value = 2)
    @Threads(2)
    @BenchmarkMode(Mode.SingleShotTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    public GroupElement hornersWithFieldElement() {
        int n = coeffPoitns.size() - 1;
        GroupElement result = coeffPoitns.get(n);
        var x = group.field().fromLong(xInt);
        for (int i = n - 1; i >= 0; i--) {
            result = result.multiply(x).add(coeffPoitns.get(i));
        }
        return result;
    }

    @Benchmark
    @Fork(value = 2)
    @Threads(2)
    @BenchmarkMode(Mode.SingleShotTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    public GroupElement hornersWithLong() {
        int n = coeffPoitns.size() - 1;
        GroupElement result = coeffPoitns.get(n);
        for (int i = n - 1; i >= 0; i--) {
            result = result.multiply(xInt).add(coeffPoitns.get(i));
        }
        return result;
    }

    @Benchmark
    @Fork(value = 2)
    @Threads(2)
    @BenchmarkMode(Mode.SingleShotTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    public GroupElement mbcWithFieldElement() {
        var x = group.field().fromLong(xInt);
        List<FieldElement> a = new ArrayList<>(degree);
        a.add(group.field().fromLong(1));
        for (int i = 1; i < degree; i++) {
            a.add(x.power(i));
        }
        return group.msm(coeffPoitns, a);
    }

    @Benchmark
    @Fork(value = 2)
    @Threads(2)
    @BenchmarkMode(Mode.SingleShotTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.MILLISECONDS)
    public GroupElement mbcWithLong() {
        long[] a = new long[degree];
        a[0] = 1;
        for (int i = 1; i < degree; i++) {
            a[i] = power(xInt, i);
        }
        return group.msm(coeffPoitns, a);
    }

    public long power(int base, int k) {
        for (long accum = 1, b = base; ; k >>>= 1)
            switch (k) {
                case 0:
                    return accum;
                case 1:
                    return accum * b;
                default:
                    if ((k & 1) != 0) // guava uses conditional multiplicand
                    accum *= b;
                    b *= b;
            }
    }
}
