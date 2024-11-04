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

package com.hedera.cryptography.bls.test.fixtures;

import com.hedera.cryptography.bls.BlsKeyPair;
import com.hedera.cryptography.bls.BlsSignature;
import com.hedera.cryptography.bls.SignatureSchema;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

public class BlsTestUtils {
    public static @NonNull List<BlsKeyPair> generateKeyPairs(
            @NonNull final SignatureSchema schema, final int numberOfPairs) {
        final Random random = new Random();
        return Stream.generate(() -> BlsKeyPair.generate(schema, random))
                .limit(numberOfPairs)
                .toList();
    }

    public static List<BlsSignature> bulkSign(@NonNull final List<BlsKeyPair> pairs, @NonNull final byte[] message) {
        return pairs.stream().map(p -> p.privateKey().sign(message)).toList();
    }

    public static @NonNull byte[] randomBytes(final long seed, final int size) {
        final byte[] bytes = new byte[size];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }
}
