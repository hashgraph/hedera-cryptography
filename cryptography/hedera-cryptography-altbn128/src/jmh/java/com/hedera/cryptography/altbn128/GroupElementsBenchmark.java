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

import com.hedera.cryptography.altbn128.facade.GroupFacade.ToBytesFlags;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import java.math.BigInteger;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Fork(value = 1, warmups = 1)
public class GroupElementsBenchmark {
    AltBn128Group group;
    Random rng = new Random();
    FieldElement element;
    GroupElement point;
    GroupElement point2;
    byte[] point2Array;
    Serializer<GroupElement> compressedSerializer;
    Deserializer<GroupElement> compressedDeserializer;
    Deserializer<GroupElement> deserializer;
    Serializer<GroupElement> serializer;

    @Param({"GROUP1", "GROUP2"})
    static String value;

    // Benchmark                                     (value)  Mode  Cnt   Score    Error  Units
    // GroupElementsBenchmark.copy                    GROUP1  avgt    5  ≈ 10⁻⁵           ms/op
    // GroupElementsBenchmark.copy                    GROUP2  avgt    5  ≈ 10⁻⁵           ms/op
    // GroupElementsBenchmark.createRandom            GROUP1  avgt    5   0.012 ±  0.001  ms/op
    // GroupElementsBenchmark.createRandom            GROUP2  avgt    5   0.187 ±  0.001  ms/op
    // GroupElementsBenchmark.fromBytesCompress       GROUP1  avgt    5   0.042 ±  0.001  ms/op
    // GroupElementsBenchmark.fromBytesCompress       GROUP2  avgt    5   0.115 ±  0.001  ms/op
    // GroupElementsBenchmark.fromBytesNonValidated   GROUP1  avgt    5  ≈ 10⁻³           ms/op
    // GroupElementsBenchmark.fromBytesNonValidated   GROUP2  avgt    5  ≈ 10⁻³           ms/op
    // GroupElementsBenchmark.fromX                   GROUP1  avgt    5   0.048 ±  0.002  ms/op
    // GroupElementsBenchmark.fromX                   GROUP2  avgt    5   0.134 ±  0.001  ms/op
    // GroupElementsBenchmark.fromXAndY               GROUP1  avgt    5   0.043 ±  0.001  ms/op
    // GroupElementsBenchmark.fromXAndY               GROUP2  avgt    5   0.117 ±  0.003  ms/op
    // GroupElementsBenchmark.multiply                GROUP1  avgt    5   0.054 ±  0.001  ms/op
    // GroupElementsBenchmark.multiply                GROUP2  avgt    5   0.159 ±  0.001  ms/op
    // GroupElementsBenchmark.multiplyLong            GROUP1  avgt    5   0.022 ±  0.001  ms/op
    // GroupElementsBenchmark.multiplyLong            GROUP2  avgt    5   0.058 ±  0.001  ms/op
    // GroupElementsBenchmark.zero                    GROUP1  avgt    5  ≈ 10⁻⁴           ms/op
    // GroupElementsBenchmark.zero                    GROUP2  avgt    5  ≈ 10⁻⁴           ms/op

    @Setup(Level.Trial)
    public void init() {
        var field = new AltBn128Field();
        group = new AltBn128Group(AltBN128CurveGroup.valueOf(value), field);
        point = group.random(rng);
        point2 = group.random(rng);
        point2Array = point2.toBytes();
        element = field.random(rng);
    }

    @Benchmark
    public GroupElement createRandom() {
        return group.random(rng);
    }

    @Benchmark
    public GroupElement fromXAndY(CoordinatesState state) {
        return group.fromCoordinates(state.xs, state.ys);
    }

    @Benchmark
    public GroupElement fromX(CoordinatesState state) {
        return group.fromXCoordinate(state.xs, false);
    }

    @Benchmark
    public GroupElement fromBytesNonValidated() {
        return group.fromBytes(point2Array, ToBytesFlags.SKIP_VALIDATE);
    }

    @Benchmark
    public GroupElement fromBytesCompress() {
        return group.fromBytes(point2Array, ToBytesFlags.COMPRESS);
    }

    @Benchmark
    public GroupElement multiply() {
        return point.multiply(element);
    }

    @Benchmark
    public GroupElement multiplyLong() {
        return point.multiply(Long.MAX_VALUE);
    }

    @Benchmark
    public GroupElement copy() {
        return point.copy();
    }

    @Benchmark
    public GroupElement zero() {
        return group.zero();
    }

    @State(Scope.Benchmark)
    public static class CoordinatesState {
        List<BigInteger> xs;
        List<BigInteger> ys;

        @Setup
        public void setup() {
            if ("GROUP1".equals(value)) {
                xs = List.of(
                        new BigInteger("4503322228978077916651710446042370109107355802721800704639343137502100212473"));
                ys = List.of(
                        new BigInteger("6132642251294427119375180147349983541569387941788025780665104001559216576968"));
            } else {
                xs = List.of(
                        new BigInteger("20954117799226682825035885491234530437475518021362091509513177301640194298072"),
                        new BigInteger("4540444681147253467785307942530223364530218361853237193970751657229138047649"));
                ys = List.of(
                        new BigInteger("21508930868448350162258892668132814424284302804699005394342512102884055673846"),
                        new BigInteger(
                                "11631839690097995216017572651900167465857396346217730511548857041925508482915"));
            }
        }
    }
}
