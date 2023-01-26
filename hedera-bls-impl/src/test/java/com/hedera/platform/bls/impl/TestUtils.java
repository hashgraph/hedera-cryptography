/*
 * Copyright (C) 2022-2023 Hedera Hashgraph, LLC
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
package com.hedera.platform.bls.impl;

import java.security.SecureRandom;
import java.util.Random;

/** A class containing various utility functions used for testing */
public class TestUtils {
    private static final Random RANDOM = new SecureRandom();

    /** Hidden constructor */
    private TestUtils() {}

    /**
     * Creates a byte array of specified size, filled with random values
     *
     * @param random a source of randomness
     * @param size the desired size of the output array
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
