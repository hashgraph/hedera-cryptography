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

import com.hedera.platform.bls.api.Group;
import com.hedera.platform.bls.api.GroupElement;
import java.util.Collection;

/**
 * G1 of the BLS12-381 curve family
 *
 * <p>This class functions as a {@link BLS12381Group1Element} factory. It is defined as a singleton.
 */
public class BLS12381Group1 implements Group {
    /** Length of a byte array representing a compressed element */
    private static final int COMPRESSED_SIZE = 48;

    /** Length of a byte array representing an uncompressed element */
    private static final int UNCOMPRESSED_SIZE = 96;

    /** Required size of a seed to create a new group element */
    private static final int SEED_SIZE = 32;

    /** The singleton instance */
    private static BLS12381Group1 instance;

    /** Hidden constructor */
    private BLS12381Group1() {}

    /**
     * Returns the singleton
     *
     * @return the singleton
     */
    public static BLS12381Group1 getInstance() {
        if (instance == null) {
            synchronized (BLS12381Group1.class) {
                if (instance != null) {
                    return instance;
                }

                instance = new BLS12381Group1();
            }
        }

        return instance;
    }

    /** {@inheritDoc} */
    @Override
    public GroupElement oneElement() {
        final byte[] output = new byte[UNCOMPRESSED_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.newG1Identity(output)) != 0) {
            throw new BLS12381Exception("newG1Identity", errorCode);
        }

        return new BLS12381Group1Element(output);
    }

    /** {@inheritDoc} */
    @Override
    public GroupElement randomElement(final byte[] seed) {
        if (seed.length != SEED_SIZE) {
            throw new IllegalArgumentException(
                    String.format("seed must be %d bytes in length", SEED_SIZE));
        }

        final byte[] output = new byte[UNCOMPRESSED_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.newRandomG1(seed, output)) != 0) {
            throw new BLS12381Exception("newRandomG1", errorCode);
        }

        return new BLS12381Group1Element(output);
    }

    /** {@inheritDoc} */
    @Override
    public GroupElement hashToGroup(final byte[] input) {
        return randomElement(Utils.computeSha256(input));
    }

    /** {@inheritDoc} */
    @Override
    public GroupElement batchMultiply(final Collection<GroupElement> elements) {
        if (elements.isEmpty()) {
            throw new IllegalArgumentException("Empty collection is invalid");
        }

        if (elements.contains(null)) {
            throw new IllegalArgumentException("invalid element in collection");
        }

        final BLS12381Group1Element[] elementArray = new BLS12381Group1Element[elements.size()];

        int count = 0;
        for (final GroupElement element : elements) {
            elementArray[count] = (BLS12381Group1Element) element;
            ++count;
        }

        final byte[] output = new byte[UNCOMPRESSED_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g1BatchMultiply(elementArray, output)) != 0) {
            throw new BLS12381Exception("g1BatchMultiply", errorCode);
        }

        return new BLS12381Group1Element(output);
    }

    /** {@inheritDoc} */
    @Override
    public GroupElement deserializeElementFromBytes(final byte[] inputBytes) {
        // create the object, but check validity before returning
        final BLS12381Group1Element outputElement = new BLS12381Group1Element(inputBytes);

        if (!outputElement.isValid()) {
            return null;
        }

        return outputElement;
    }

    /** {@inheritDoc} */
    @Override
    public int getCompressedSize() {
        return COMPRESSED_SIZE;
    }

    /** {@inheritDoc} */
    @Override
    public int getUncompressedSize() {
        return UNCOMPRESSED_SIZE;
    }

    /** {@inheritDoc} */
    @Override
    public int getSeedSize() {
        return SEED_SIZE;
    }
}
