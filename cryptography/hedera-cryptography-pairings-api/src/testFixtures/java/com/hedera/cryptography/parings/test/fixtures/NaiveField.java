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

package com.hedera.cryptography.parings.test.fixtures;

import static com.hedera.cryptography.parings.test.fixtures.NaiveCurve.EXAMPLE_SIZE;

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.Random;

/**
 * A naive implementation of the Field interface for testing purposes.
 * This implementation provides basic methods to create field elements from various inputs.
 */
public class NaiveField implements Field {

    private final PairingFriendlyCurve curve;

    /**
     * Constructs a NaiveField with the specified pairing-friendly curve.
     *
     * @param curve the pairing-friendly curve associated with this field
     */
    public NaiveField(final PairingFriendlyCurve curve) {
        this.curve = curve;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public FieldElement random(@NonNull final Random random) {
        return fromLong(random.nextLong());
    }

    /**
     * Creates a field element from a long value.
     * The value is reduced modulo the prime modulus.
     *
     * @param inputLong the long value
     * @return a field element representing the long value
     */
    @Override
    @NonNull
    public FieldElement fromLong(final long inputLong) {
        return new NaiveFieldElement(this, BigInteger.valueOf(inputLong));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public FieldElement random(@NonNull final byte[] seed) {
        return new NaiveFieldElement(this, new BigInteger(seed));
    }

    /**
     * Creates a field element from a byte array.
     * The value is reduced modulo the prime modulus.
     *
     * @param bytes the byte array
     * @return a field element representing the byte array
     */
    @Override
    @NonNull
    public FieldElement fromBytes(@NonNull final byte[] bytes) {
        return new NaiveFieldElement(this, new BigInteger(bytes));
    }

    /**
     * Creates a field element from a BigInteger.
     * The value is reduced modulo the prime modulus.
     *
     * @param bigInteger the BigInteger
     * @return a field element representing the BigInteger
     */
    @Override
    @NonNull
    public FieldElement fromBigInteger(@NonNull final BigInteger bigInteger) {
        return new NaiveFieldElement(this, bigInteger);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int elementSize() {
        return EXAMPLE_SIZE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int seedSize() {
        return EXAMPLE_SIZE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public PairingFriendlyCurve getPairingFriendlyCurve() {
        return curve;
    }
}
