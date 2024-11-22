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

package com.hedera.cryptography.pairings.test.fixtures.curve;

import static com.hedera.cryptography.pairings.test.fixtures.curve.NaiveCurve.EXAMPLE_SIZE;
import static com.hedera.cryptography.pairings.test.fixtures.curve.NaiveFieldElement.PRIME_MODULUS;

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.utils.HashUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * A naive implementation of the Group interface for testing purposes.
 * This implementation provides basic methods to interact with group elements.
 */
public class NaiveGroup implements Group {
    private final PairingFriendlyCurve curve;

    /**
     * Constructs a NaiveGroup with the specified pairing-friendly curve.
     *
     * @param curve the pairing-friendly curve associated with this group
     */
    public NaiveGroup(@NonNull final PairingFriendlyCurve curve) {
        this.curve = Objects.requireNonNull(curve, "curve must not be null");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public PairingFriendlyCurve getPairingFriendlyCurve() {
        return curve;
    }

    @NonNull
    @Override
    public Field field() {
        return curve.field();
    }

    /**
     * Returns a simple generator for demonstration purposes.
     *
     * @return the generator of the group
     */
    @Override
    @NonNull
    public GroupElement generator() {
        return new NaiveGroupElement(this, BigInteger.valueOf(2));
    }

    /**
     * Returns the zero element for the group, representing the identity element.
     *
     * @return the zero element of the group
     */
    @Override
    @NonNull
    public GroupElement zero() {
        return new NaiveGroupElement(this, BigInteger.ZERO);
    }

    @NonNull
    @Override
    public GroupElement mbc(final List<GroupElement> elements, final List<FieldElement> scalars) {
        Objects.requireNonNull(elements, "elements must not be null");
        Objects.requireNonNull(scalars, "scalars must not be null");

        GroupElement result = elements.get(0).multiply(scalars.get(0));
        for (int i = 1; i < elementSize(); i++) {
            result = result.add(elements.get(i).multiply(scalars.get(i)));
        }
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement random(@NonNull final byte[] seed) {
        final BigInteger value = new BigInteger(seed).mod(PRIME_MODULUS);
        return new NaiveGroupElement(this, value);
    }

    /**
     * Hashes the input bytes to a group element.
     * Uses SHA-256 to hash the input and ensures the result is within the group size.
     *
     * @param input the input bytes
     * @return the group element resulting from the hash
     */
    @Override
    @NonNull
    public GroupElement hashToCurve(@NonNull final byte[] input) {
        final byte[] hash = HashUtils.computeHash(HashUtils.SHA256, input);
        final BigInteger value = new BigInteger(1, hash).mod(PRIME_MODULUS);

        return new NaiveGroupElement(this, value);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement add(@NonNull final Collection<GroupElement> elements) {
        BigInteger sum = BigInteger.ZERO;
        for (final GroupElement element : elements) {
            sum = sum.add(((NaiveGroupElement) element).value()).mod(PRIME_MODULUS);
        }
        return new NaiveGroupElement(this, sum);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement fromBytes(@NonNull final byte[] bytes) {
        final BigInteger value = new BigInteger(bytes).mod(PRIME_MODULUS);
        return new NaiveGroupElement(this, value);
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
    public int elementSize() {
        return EXAMPLE_SIZE;
    }
}
