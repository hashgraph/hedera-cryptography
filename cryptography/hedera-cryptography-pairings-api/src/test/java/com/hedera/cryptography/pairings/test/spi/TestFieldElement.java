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

package com.hedera.cryptography.pairings.test.spi;

import static com.hedera.cryptography.pairings.test.spi.TestPairingFriendlyCurve.BYTES;

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;

/**
 * Fake implementation of a {@link FieldElement}
 */
record TestFieldElement(Field field) implements FieldElement {
    /** {@inheritDoc} */
    @NonNull
    @Override
    public Field field() {
        return field;
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public FieldElement add(@NonNull final FieldElement other) {
        return new TestFieldElement(field);
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public FieldElement subtract(@NonNull final FieldElement other) {
        return new TestFieldElement(field);
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public FieldElement multiply(@NonNull final FieldElement other) {
        return new TestFieldElement(field);
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public FieldElement power(final long exponent) {
        return new TestFieldElement(field);
    }

    @NonNull
    @Override
    public FieldElement inverse() {
        return new TestFieldElement(field);
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public BigInteger toBigInteger() {
        return new BigInteger(toBytes());
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public byte[] toBytes() {
        return BYTES;
    }
}
