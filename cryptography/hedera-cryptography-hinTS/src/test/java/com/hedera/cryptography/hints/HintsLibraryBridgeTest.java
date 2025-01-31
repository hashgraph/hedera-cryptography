// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class HintsLibraryBridgeTest {
    private static final HintsLibraryBridge INSTANCE = HintsLibraryBridge.getInstance();

    @Test
    void testGenerateSecretKey() {
        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);
    }

    @Test
    void testComputeHints() {
        final byte[] crs = INSTANCE.initCRS(4);
        assertArrayEquals(CRSConstants.INIT_CRS_4, crs);

        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);

        final byte[] hints = INSTANCE.computeHints(crs, secretKey, 2, 4);

        assertArrayEquals(HintsConstants.HINTS, hints);
    }

    @Test
    void testValidateHintsKey() {
        final byte[] crs = INSTANCE.initCRS(4);
        assertArrayEquals(CRSConstants.INIT_CRS_4, crs);

        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);

        final byte[] hints = INSTANCE.computeHints(crs, secretKey, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints);

        assertTrue(INSTANCE.validateHintsKey(crs, hints, 2, 4));
    }

    @Test
    void testPreprocess() {
        final byte[] crs = INSTANCE.initCRS(4);
        assertArrayEquals(CRSConstants.INIT_CRS_4, crs);

        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);

        final byte[] hints = INSTANCE.computeHints(crs, secretKey, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints);

        final AggregationAndVerificationKeys keys =
                INSTANCE.preprocess(crs, new int[] {2}, new byte[][] {hints}, new long[] {111}, 4);
        assertArrayEquals(HintsConstants.VERIFICATION_KEY, keys.verificationKey());
        assertArrayEquals(HintsConstants.AGGREGATION_KEY, keys.aggregationKey());
    }

    @Test
    void testSignBls() {
        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);

        // Use the RANDOM as a message to sign, because why not?
        final byte[] signature = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey);
        assertArrayEquals(HintsConstants.SIGNATURE, signature);
    }

    @Test
    void testVerifyBls() {
        final byte[] crs = INSTANCE.initCRS(4);
        assertArrayEquals(CRSConstants.INIT_CRS_4, crs);

        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);

        final byte[] hints = INSTANCE.computeHints(crs, secretKey, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints);

        // Use the RANDOM as a message to sign, because why not?
        final byte[] signature = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey);
        assertArrayEquals(HintsConstants.SIGNATURE, signature);

        assertTrue(INSTANCE.verifyBls(crs, signature, HintsConstants.RANDOM_2, hints));
    }

    @Test
    void testAggregateSignatures() {
        final byte[] crs = INSTANCE.initCRS(4);
        assertArrayEquals(CRSConstants.INIT_CRS_4, crs);

        // partyId 2
        final byte[] secretKey1 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey1);
        final byte[] hints1 = INSTANCE.computeHints(crs, secretKey1, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints1);
        // Use the RANDOM as a message to sign, because why not?
        final byte[] signature1 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey1);
        assertArrayEquals(HintsConstants.SIGNATURE, signature1);

        // partyId 0
        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, 0, 4);
        final byte[] signature2 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey2);

        final AggregationAndVerificationKeys keys =
                INSTANCE.preprocess(crs, new int[] {0, 2}, new byte[][] {hints2, hints1}, new long[] {111, 222}, 4);

        final byte[] result = INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, new byte[][] {
                    signature1, signature2
                });

        assertArrayEquals(HintsConstants.AGGREGATE_SIGNATURE, result);
    }

    @Test
    void testVerifyAggregate_meetsThreshold() {
        final byte[] crs = INSTANCE.initCRS(4);
        assertArrayEquals(CRSConstants.INIT_CRS_4, crs);

        // partyId 2
        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey2);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints2);
        // Use the RANDOM as a message to sign, because why not?
        final byte[] signature2 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey2);
        assertArrayEquals(HintsConstants.SIGNATURE, signature2);

        // partyId 0
        final byte[] secretKey0 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints0 = INSTANCE.computeHints(crs, secretKey0, 0, 4);
        final byte[] signature0 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey0);

        // partyId 1
        final byte[] secretKey1 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_1);
        final byte[] hints1 = INSTANCE.computeHints(crs, secretKey1, 1, 4);

        // Here, the partyId 1 has a tiny weight of 1, so it doesn't matter
        final AggregationAndVerificationKeys keys = INSTANCE.preprocess(
                crs, new int[] {0, 2, 1}, new byte[][] {hints0, hints2, hints1}, new long[] {111, 222, 1}, 4);

        final byte[] result = INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {2, 0}, new byte[][] {
                    signature2, signature0
                });
        assertArrayEquals(HintsConstants.AGGREGATE_SIGNATURE_2, result);

        assertTrue(INSTANCE.verifyAggregate(crs, result, HintsConstants.RANDOM_2, keys.verificationKey(), 1, 3));
    }

    @Test
    void testVerifyAggregate_doesNotMeetThreshold() {
        final byte[] crs = INSTANCE.initCRS(4);
        assertArrayEquals(CRSConstants.INIT_CRS_4, crs);

        // partyId 2
        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey2);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints2);
        // Use the RANDOM as a message to sign, because why not?
        final byte[] signature2 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey2);
        assertArrayEquals(HintsConstants.SIGNATURE, signature2);

        // partyId 0
        final byte[] secretKey0 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints0 = INSTANCE.computeHints(crs, secretKey0, 0, 4);
        final byte[] signature0 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey0);

        // partyId 1
        final byte[] secretKey1 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_1);
        final byte[] hints1 = INSTANCE.computeHints(crs, secretKey1, 1, 4);

        // Here, the partyId 1 has a huge weight of 999, so it matters a lot more than the other two
        final AggregationAndVerificationKeys keys = INSTANCE.preprocess(
                crs, new int[] {0, 2, 1}, new byte[][] {hints0, hints2, hints1}, new long[] {111, 222, 999}, 4);

        final byte[] result = INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {2, 0}, new byte[][] {
                    signature2, signature0
                });
        assertArrayEquals(HintsConstants.AGGREGATE_SIGNATURE_3, result);

        assertFalse(INSTANCE.verifyAggregate(crs, result, HintsConstants.RANDOM_2, keys.verificationKey(), 1, 3));
    }
}
