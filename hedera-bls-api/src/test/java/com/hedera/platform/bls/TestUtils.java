/*
 * Copyright 2016-2022 Hedera Hashgraph, LLC
 *
 * This software is the confidential and proprietary information of
 * Hedera Hashgraph, LLC. ("Confidential Information"). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered into
 * with Hedera Hashgraph.
 *
 * HEDERA HASHGRAPH MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. HEDERA HASHGRAPH SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 */

package com.hedera.platform.bls;

import java.security.SecureRandom;
import java.util.Random;

/**
 * A class containing various utility functions used for testing
 */
public class TestUtils {
    private static final Random RANDOM = new SecureRandom();

    /**
     * Hidden constructor
     */
    private TestUtils() {
    }

    /**
     * Creates a byte array of specified size, filled with random values
     *
     * @param random a source of randomness
     * @param size   the desired size of the output array
     * @return a random byte array of size
     */
    public static byte[] randomByteArray(final Random random, final int size) {
        final byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * Gets a source of randomness and prints the corresponding seed
     *
     * @return a source of randomness
     */
    public static Random getRandomPrintSeed() {
        final long seed = RANDOM.nextLong();

        System.out.println("Random seed: " + seed);

        return new Random(seed);
    }

    /**
     * Converts a byte array to a hex string
     *
     * @param hash the byte array to convert
     * @return a hex string representing the byte array hash
     */
    public static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
