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
import com.hedera.cryptography.pairings.extensions.serialization.DefaultGroupElementSerialization;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
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
    GroupElement point;
    GroupElement point2;
    Serializer<GroupElement> compressedSerializer;
    Deserializer<GroupElement> compressedDeserializer;
    Deserializer<GroupElement> deserializer;
    Serializer<GroupElement> serializer;
    FieldElement element;

    @Param({"GROUP1", "GROUP2"})
    static String value;

    static Map<String, byte[]> representations = new HashMap<>();

    @Setup(Level.Trial)
    public void init() {
        var field = new AltBn128Field();
        group = new AltBn128Group(AltBN128CurveGroup.valueOf(value), field);
        point = group.random(rng);
        point2 = group.random(rng);
        element = field.random(rng);
        var parser = HexFormat.of().withUpperCase();
        representations.put(
                "CGROUP1", parser.parseHex("F1EE9FFEE1686777ED6873FB07900FE138F6A887D047D93F837B4D711221E283"));
        representations.put(
                "GROUP1",
                parser.parseHex(
                        "545BABA0D76CB1F5AB91D137997A6ACF4ECDDA2E3C1BF04784909DEDF1C4C5198DA77E6DC899EB46E6C9AB986EC71D19CE36493631E74FA89B81868BC96EEF01"));
        representations.put(
                "CGROUP2",
                parser.parseHex(
                        "DB6E273C0EECC178EB314E05CD3E3C43B06867A2127B99AFF2CFAFBAD005952AE752849D167C1C0DD7D4B45669038FA9C52F2E8B24C391A4EB98DE705EFD5F8D"));
        representations.put(
                "GROUP2",
                parser.parseHex(
                        "10B2661406630FAF67257CC04AED61D2CB4F0BA6709121FCEB3BF66FFD75E713A6FD2D39369D2B522E21255F26C363709417FED0E32809297776EFE912391A0A6CEC315983B781696C8CD23FD69ADCBB5DAC1F10F2F5F1BFF2592E34D30C8A22558DA61D9705AA8F65B69F8500403AE499B90A9A60399FE1CE99D5B98A9383AA"));

        serializer = DefaultGroupElementSerialization.getSerializer();
        compressedSerializer = DefaultGroupElementSerialization.getCompressSerializer();
        deserializer = DefaultGroupElementSerialization.getDeserializer(group);
        compressedDeserializer = DefaultGroupElementSerialization.getCompressedDeserializer(group);
    }
    // Benchmark                                       (value)  Mode  Cnt   Score    Error  Units
    // GroupElementsBenchmark.compressedDeserialize     GROUP1  avgt    5   0.049 ±  0.001  ms/op
    // GroupElementsBenchmark.compressedDeserialize     GROUP2  avgt    5   0.136 ±  0.002  ms/op
    // GroupElementsBenchmark.compressedSerialize       GROUP1  avgt    5  ≈ 10⁻³           ms/op
    // GroupElementsBenchmark.compressedSerialize       GROUP2  avgt    5  ≈ 10⁻³           ms/op
    // GroupElementsBenchmark.createRandom              GROUP1  avgt    5   0.012 ±  0.001  ms/op
    // GroupElementsBenchmark.createRandom              GROUP2  avgt    5   0.190 ±  0.009  ms/op
    // GroupElementsBenchmark.deserialize               GROUP1  avgt    5   0.043 ±  0.001  ms/op
    // GroupElementsBenchmark.deserialize               GROUP2  avgt    5   0.119 ±  0.005  ms/op
    // GroupElementsBenchmark.deserializeNotValidated   GROUP1  avgt    5  ≈ 10⁻³           ms/op
    // GroupElementsBenchmark.deserializeNotValidated   GROUP2  avgt    5  ≈ 10⁻³           ms/op
    // GroupElementsBenchmark.fromXAndY                 GROUP1  avgt    5   0.044 ±  0.002  ms/op
    // GroupElementsBenchmark.fromXAndY                 GROUP2  avgt    5   0.117 ±  0.003  ms/op
    // GroupElementsBenchmark.serialize                 GROUP1  avgt    5  ≈ 10⁻⁶           ms/op
    // GroupElementsBenchmark.serialize                 GROUP2  avgt    5  ≈ 10⁻⁵           ms/op
    // GroupElementsBenchmark.zero                      GROUP1  avgt    5  ≈ 10⁻⁴           ms/op
    // GroupElementsBenchmark.zero                      GROUP2  avgt    5  ≈ 10⁻⁴           ms/op

    @Benchmark
    public GroupElement createRandom() {
        return group.random(rng);
    }

    @Benchmark
    public GroupElement fromXAndY(CoordinatesState state) {
        return group.fromCoordinates(state.xs, state.ys);
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

    @Benchmark
    public byte[] serialize() {
        return serializer.serialize(point);
    }

    @Benchmark
    public byte[] compressedSerialize() {
        return compressedSerializer.serialize(point);
    }

    @Benchmark
    public GroupElement compressedDeserialize(CompressedState state) {
        return compressedDeserializer.deserialize(state.compressedBytes);
    }

    @Benchmark
    public GroupElement deserialize(UncompressState state) {
        return deserializer.deserialize(state.uncompressedBytes);
    }

    @Benchmark
    public GroupElement deserializeNotValidated(UncompressState state) {
        return group.fromBytes(state.uncompressedBytes, false);
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

    @State(Scope.Benchmark)
    public static class CompressedState {
        byte[] compressedBytes;

        @Setup
        public void setup() {
            compressedBytes = representations.get("C" + value);
        }
    }

    @State(Scope.Benchmark)
    public static class UncompressState {
        byte[] uncompressedBytes;

        @Setup
        public void setup() {
            uncompressedBytes = representations.get(value);
        }
    }
}
