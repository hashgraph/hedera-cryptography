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
package com.hedera.platform.bls;

import java.util.Collection;

/** G2 of the BLS12-381 curve family */
public class BLS12381Group2 implements Group {
    /** Length of a byte array representing a compressed element */
    private static final int COMPRESSED_SIZE = 96;

    /** Length of a byte array representing an uncompressed element */
    private static final int UNCOMPRESSED_SIZE = 192;

    /** Required size of a seed to create a new group element */
    private static final int SEED_SIZE = 32;

    /** {@inheritDoc} */
    @Override
    public GroupElement oneElement() {
        final byte[] output = new byte[UNCOMPRESSED_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.newG2Identity(output)) != 0) {
            throw new BLS12381Exception("newG2Identity", errorCode);
        }

        return new BLS12381Group2Element(output, this);
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
        if ((errorCode = BLS12381Bindings.newRandomG2(seed, output)) != 0) {
            throw new BLS12381Exception("newRandomG2", errorCode);
        }

        return new BLS12381Group2Element(output, this);
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

        final BLS12381Group2Element[] elementArray = new BLS12381Group2Element[elements.size()];

        int count = 0;
        for (final GroupElement element : elements) {
            elementArray[count] = (BLS12381Group2Element) element;
            ++count;
        }

        final byte[] output = new byte[UNCOMPRESSED_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g2BatchMultiply(elementArray, output)) != 0) {
            throw new BLS12381Exception("g2BatchMultiply", errorCode);
        }

        return new BLS12381Group2Element(output, this);
    }

    /** {@inheritDoc} */
    @Override
    public GroupElement deserializeElementFromBytes(final byte[] inputBytes) {
        // create the object, but check validity before returning
        final BLS12381Group2Element outputElement = new BLS12381Group2Element(inputBytes, this);

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

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null) {
            return false;
        }

        return getClass() == o.getClass();
    }

    @Override
    public int hashCode() {
        return this.getClass().getCanonicalName().hashCode();
    }
}
