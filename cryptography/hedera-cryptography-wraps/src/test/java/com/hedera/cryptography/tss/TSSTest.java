// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.tss;

import static com.hedera.cryptography.wraps.WRAPSLibraryBridgeTest.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;
import org.junit.jupiter.api.Test;

public class TSSTest {
    private static final byte[] EMPTY = new byte[0];
    private static final byte[] ONE = new byte[] {1};

    @Test
    void testComposeSignature() {
        // Happy cases first
        assertArrayEquals(
                TSSTestConstants.TSS_SIGNATURE_WITH_SCHNORR,
                TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertArrayEquals(
                TSSTestConstants.TSS_SIGNATURE_WITH_WRAPS,
                TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF));

        // Unhappy cases last
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, TSSTestConstants.HINTS_SIGNATURE, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, TSSTestConstants.HINTS_SIGNATURE, EMPTY));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, TSSTestConstants.HINTS_SIGNATURE, ONE));

        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        null, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        EMPTY, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        ONE, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, null, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, EMPTY, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, ONE, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));

        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        null, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        EMPTY, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        ONE, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, null, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, EMPTY, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, ONE, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
    }

    /**
     * An arrays concatenator.
     * @param arrays byte arrays
     * @return a concatenated array in the order present
     */
    private byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] arr : arrays) {
            len += arr.length;
        }

        final byte[] ret = new byte[len];

        int pos = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, ret, pos, arr.length);
            pos += arr.length;
        }

        return ret;
    }

    /**
     * Randomly corrupted array copier.
     * @param arr an input array
     * @param rnd a Random
     * @return a copy of arr with one random byte randomly modified
     */
    private byte[] rnd(byte[] arr, Random rnd) {
        final byte[] clone = arr.clone();
        final int val = rnd.nextInt(256);
        final int i = rnd.nextInt(clone.length);

        if (clone[i] == val) {
            clone[i] = (byte) (val == 0 ? 1 : val + 1);
        } else {
            clone[i] = (byte) val;
        }

        return clone;
    }

    @Test
    void testVerifyTSS() {
        // A fixed seed for reproducibility:
        final Random rnd = new Random(945863847);

        // Two happy cases first:

        TSS.setSchnorrPublicKeys(TSSTestConstants.SCHNORR_PUBLIC_KEYS);
        assertTrue(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                TSSTestConstants.MESSAGE));

        TSS.setSchnorrPublicKeys(null);
        assertTrue(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                TSSTestConstants.MESSAGE));

        // Then unhappy cases, starting with unverifiable data
        assertFalse(TSS.verifyTSS(
                rnd(TSSTestConstants.ADDRESS_BOOK_HASH, rnd),
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        rnd(TSSTestConstants.HINTS_VERIFICATION_KEY, rnd),
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        rnd(TSSTestConstants.HINTS_SIGNATURE, rnd),
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        rnd(TSSTestConstants.COMPRESSED_WRAPS_PROOF, rnd)),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                rnd(TSSTestConstants.MESSAGE, rnd)));

        TSS.setSchnorrPublicKeys(TSSTestConstants.SCHNORR_PUBLIC_KEYS);
        assertFalse(TSS.verifyTSS(
                rnd(TSSTestConstants.ADDRESS_BOOK_HASH, rnd),
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        rnd(TSSTestConstants.HINTS_VERIFICATION_KEY, rnd),
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        rnd(TSSTestConstants.HINTS_SIGNATURE, rnd),
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        rnd(TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE, rnd)),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                rnd(TSSTestConstants.MESSAGE, rnd)));
        final byte[][] badSchnorrKeys = new byte[TSSTestConstants.SCHNORR_PUBLIC_KEYS.length][];
        for (int i = 0; i < TSSTestConstants.SCHNORR_PUBLIC_KEYS.length; i++) {
            badSchnorrKeys[i] = TSSTestConstants.SCHNORR_PUBLIC_KEYS[i];
            if (i == 0) {
                badSchnorrKeys[i] = rnd(badSchnorrKeys[i], rnd);
            }
        }
        TSS.setSchnorrPublicKeys(badSchnorrKeys);
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                TSSTestConstants.MESSAGE));

        // Then test the missing keys
        TSS.setSchnorrPublicKeys(null);
        assertThrows(
                IllegalStateException.class,
                () -> TSS.verifyTSS(
                        TSSTestConstants.ADDRESS_BOOK_HASH,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                        TSSTestConstants.MESSAGE));

        // And finally check bad args
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        null,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                        TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        EMPTY,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                        TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        ONE,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                        TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(TSSTestConstants.ADDRESS_BOOK_HASH, null, TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(TSSTestConstants.ADDRESS_BOOK_HASH, EMPTY, TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        TSSTestConstants.ADDRESS_BOOK_HASH,
                        concat(TSSTestConstants.HINTS_VERIFICATION_KEY, new byte[] {1, 2, 3}, new byte[] {1, 2, 3}),
                        TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        TSSTestConstants.ADDRESS_BOOK_HASH,
                        concat(TSSTestConstants.HINTS_VERIFICATION_KEY, TSSTestConstants.HINTS_SIGNATURE, new byte[] {
                            1, 2, 3
                        }),
                        TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        TSSTestConstants.ADDRESS_BOOK_HASH,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                        null));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        TSSTestConstants.ADDRESS_BOOK_HASH,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                        EMPTY));
    }
}
