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
import com.hedera.cryptography.bls.BlsSignature;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssShareSignature;
import com.hedera.cryptography.tss.test.fixtures.TssTestCommittee;
import com.hedera.cryptography.tss.test.fixtures.TssTestUtils;
import java.util.Collection;
import java.util.List;
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
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Timeout;
import org.openjdk.jmh.annotations.Warmup;

/**
 * A test to showcase the Tss protocol for a specific case
 * More validations can be added once
 */
@State(Scope.Benchmark)
@Timeout(time = 10, timeUnit = TimeUnit.HOURS)
@Fork(value = 1)
@Threads(1)
@Warmup(iterations = 0)
@Measurement(iterations = 1)
@BenchmarkMode(Mode.SingleShotTime)
@OutputTimeUnit(TimeUnit.SECONDS)
public class TssSignaturesBenchmark {

    @Param({"130"})
    static int participants;

    @Param({"10"})
    static int shares;

    @Param({"SHORT_SIGNATURES", "SHORT_PUBLIC_KEYS"})
    static GroupAssignment groupAssignment;

    @Benchmark
    public List<?> p0Signs(TssSignatureState state) {
        return state.privateShares.getFirst().stream()
                .map(s -> s.sign(state.message))
                .toList();
    }

    @Benchmark
    public BlsSignature signatureAggregation(TssSignatureState state) {
        return TssShareSignature.aggregate(state.allSignatures);
    }

    @State(Scope.Benchmark)
    public static class TssSignatureState {
        byte[] message;
        List<TssShareSignature> signatures;

        @Param({"32", "256", "1024"})
        public int messageSize;

        BlsPublicKey ledgerId;
        List<TssShareSignature> allSignatures;
        List<List<TssPrivateShare>> privateShares;

        @Setup
        public void init() {
            this.message = new byte[messageSize];
            Random rng = new Random();
            rng.nextBytes(message);
            SignatureSchema signatureSchema = SignatureSchema.create(Curve.ALT_BN128, groupAssignment);
            final BlsPrivateKey[] keys = TssTestUtils.rndSks(signatureSchema, rng, participants);
            this.privateShares = TssTestUtils.randomPrivateShares(
                    new TssTestCommittee(participants, shares, keys), rng, signatureSchema);
            var publicShares = privateShares.stream()
                    .map(l -> l.stream()
                            .map(sk -> new TssPublicShare(
                                    sk.shareId(), sk.privateKey().createPublicKey()))
                            .toList())
                    .toList();
            var allPublicShares =
                    publicShares.stream().flatMap(Collection::stream).toList();
            this.ledgerId = TssPublicShare.aggregate(allPublicShares);
            this.allSignatures = privateShares.stream()
                    .flatMap(l -> l.stream().map(s -> s.sign(message)))
                    .toList();
        }
    }
}
