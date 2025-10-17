// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.wraps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class WRAPSLibraryBridgeTest {
    private static final WRAPSLibraryBridge WRAPS = WRAPSLibraryBridge.getInstance();
    private static final byte[][] EMPTY_BYTE_ARRAY_2 = new byte[0][];

    // A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    public static void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }

    @Test
    public void testGenerateSchnorrKeys() {
        final SchnorrKeys schnorrKeys = WRAPS.generateSchnorrKeys(Constants.SEED_0);

        assertArrayEquals(Constants.SCHNORR_PRIVATE_KEY_0, schnorrKeys.privateKey());
        assertArrayEquals(Constants.SCHNORR_PUBLIC_KEY_0, schnorrKeys.publicKey());

        // Verify if a different seed generates different keys:
        final SchnorrKeys keys1 = WRAPS.generateSchnorrKeys(Constants.SEED_1);
        assertFalse(Arrays.equals(keys1.privateKey(), schnorrKeys.privateKey()));
        assertFalse(Arrays.equals(keys1.publicKey(), schnorrKeys.publicKey()));
    }

    @Test
    public void testGenerateSchnorrKeysConstraints() {
        assertEquals(null, WRAPS.generateSchnorrKeys(null));
        assertEquals(null, WRAPS.generateSchnorrKeys(new byte[0]));

        // length less than ENTROPY_SIZE:
        assertEquals(null, WRAPS.generateSchnorrKeys(new byte[] {1, 2, 3}));

        // length greater than ENTROPY_SIZE:
        byte[] tooLargeArray = new byte[WRAPSLibraryBridge.ENTROPY_SIZE + 3];
        assertEquals(null, WRAPS.generateSchnorrKeys(tooLargeArray));
    }

    private byte[][] listToArray(List<byte[]> list) {
        return list.toArray(new byte[list.size()][]);
    }

    @Test
    public void testRunSigningProtocolPhase() {
        if (true) {
            return;
        }
        record SeedAndKey(byte[] seed, SchnorrKeys keys) {}
        final List<SeedAndKey> seedsAndKeys = List.of(Constants.SEED_0, Constants.SEED_1, Constants.SEED_2).stream()
                .map(seed -> new SeedAndKey(seed, WRAPS.generateSchnorrKeys(seed)))
                .toList();

        final byte[][] pubKeys = listToArray(
                seedsAndKeys.stream().map(sk -> sk.keys().publicKey()).toList());

        final List<byte[]> round1 = seedsAndKeys.stream()
                .map(sk -> WRAPS.runSigningProtocolPhase(
                        WRAPSLibraryBridge.SigningProtocolPhase.R1,
                        sk.seed(),
                        Constants.MESSAGE,
                        sk.keys().privateKey(),
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2))
                .peek(ba -> System.err.println(Arrays.toString(ba)))
                .toList();
        final byte[][] round1Array = listToArray(round1);

        final List<byte[]> round2 = seedsAndKeys.stream()
                .map(sk -> WRAPS.runSigningProtocolPhase(
                        WRAPSLibraryBridge.SigningProtocolPhase.R2,
                        sk.seed(),
                        Constants.MESSAGE,
                        sk.keys().privateKey(),
                        pubKeys,
                        round1Array,
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2))
                .peek(ba -> System.err.println(Arrays.toString(ba)))
                .toList();
        final byte[][] round2Array = listToArray(round2);

        final List<byte[]> round3 = seedsAndKeys.stream()
                .map(sk -> WRAPS.runSigningProtocolPhase(
                        WRAPSLibraryBridge.SigningProtocolPhase.R3,
                        sk.seed(),
                        Constants.MESSAGE,
                        sk.keys().privateKey(),
                        pubKeys,
                        round1Array,
                        round2Array,
                        EMPTY_BYTE_ARRAY_2))
                .peek(ba -> System.err.println(Arrays.toString(ba)))
                .toList();
        final byte[][] round3Array = listToArray(round3);

        final byte[] signature = WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                Constants.MESSAGE,
                null,
                pubKeys,
                round1Array,
                round2Array,
                round3Array);

        System.err.println(Arrays.toString(signature));
    }
}
