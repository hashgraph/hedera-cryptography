package com.hedera.cryptography.bls.test.fixtures;

import com.hedera.cryptography.bls.BlsKeyPair;
import com.hedera.cryptography.bls.BlsSignature;
import com.hedera.cryptography.bls.SignatureSchema;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

public class BlsTestUtils {
    public static @NonNull List<BlsKeyPair> generateKeyPairs(@NonNull final SignatureSchema schema, final int numberOfPairs) {
        final Random random = new Random();
        return Stream.generate(() -> BlsKeyPair.generate(schema, random))
                .limit(numberOfPairs)
                .toList();
    }

    public static List<BlsSignature> bulkSign(@NonNull final  List<BlsKeyPair> pairs, @NonNull final byte[] message) {
        return pairs.stream()
                .map(p -> p.privateKey().sign(message))
                .toList();
    }

    public static @NonNull byte[] randomBytes(final long seed, final int size) {
        final byte[] bytes = new byte[size];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }
}
