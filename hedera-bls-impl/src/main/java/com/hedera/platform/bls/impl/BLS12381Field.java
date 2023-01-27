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

import static com.hedera.platform.bls.impl.BLS12381Bindings.SUCCESS;

import com.hedera.platform.bls.api.Field;
import com.hedera.platform.bls.api.FieldElement;

/**
 * The finite field of the BLS 12-381 curve family
 *
 * <p>This class functions as a {@link BLS12381FieldElement} factory. It is defined as a singleton.
 */
public class BLS12381Field implements Field {

    /** Required size of a seed to create a new field element */
    public static final int SEED_SIZE = 32;

    /** Length of a byte array representing a field element */
    public static final int ELEMENT_BYTE_SIZE = 32;

    /** The singleton instance */
    private static BLS12381Field instance;

    /** Hidden constructor */
    private BLS12381Field() {}

    /**
     * Returns the singleton
     *
     * @return the singleton
     */
    public static BLS12381Field getInstance() {
        if (instance == null) {
            synchronized (BLS12381Field.class) {
                if (instance != null) {
                    return instance;
                }

                instance = new BLS12381Field();
            }
        }

        return instance;
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement elementFromLong(final long inputLong) {
        final byte[] output = new byte[ELEMENT_BYTE_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.newScalarFromLong(inputLong, output)) != SUCCESS) {
            throw new BLS12381Exception("newScalarFromLong", errorCode);
        }

        return new BLS12381FieldElement(output);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement zeroElement() {
        final byte[] output = new byte[ELEMENT_BYTE_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.newZeroScalar(output)) != SUCCESS) {
            throw new BLS12381Exception("newZeroScalar", errorCode);
        }

        return new BLS12381FieldElement(output);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement oneElement() {
        final byte[] output = new byte[ELEMENT_BYTE_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.newOneScalar(output)) != SUCCESS) {
            throw new BLS12381Exception("newOneScalar", errorCode);
        }

        return new BLS12381FieldElement(output);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement randomElement(final byte[] seed) {
        if (seed.length != SEED_SIZE) {
            throw new IllegalArgumentException(
                    String.format("seed must be %s bytes in length", SEED_SIZE));
        }

        final byte[] output = new byte[ELEMENT_BYTE_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.newRandomScalar(seed, output)) != SUCCESS) {
            throw new BLS12381Exception("newRandomScalar", errorCode);
        }

        return new BLS12381FieldElement(output);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement deserializeElementFromBytes(final byte[] bytes) {
        final BLS12381FieldElement outputElement = new BLS12381FieldElement(bytes);

        if (!outputElement.isValid()) {
            return null;
        }

        return outputElement;
    }

    /** {@inheritDoc} */
    @Override
    public int getElementSize() {
        return ELEMENT_BYTE_SIZE;
    }

    /** {@inheritDoc} */
    @Override
    public int getSeedSize() {
        return SEED_SIZE;
    }
}
