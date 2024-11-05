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

import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

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
    public NaiveGroup(final PairingFriendlyCurve curve) {
        this.curve = curve;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public PairingFriendlyCurve getPairingFriendlyCurve() {
        return curve;
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

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement random(@NonNull final byte[] seed) {
        final BigInteger value = new BigInteger(seed).mod(BigInteger.valueOf(23));
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
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            final byte[] hash = md.digest(input);
            final BigInteger value = new BigInteger(1, hash).mod(BigInteger.valueOf(23));
            return new NaiveGroupElement(this, value);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Adds a collection of group elements and returns the result.
     * Sums the values of the provided group elements and ensures the result is within the group size.
     *
     * @param elements the collection of group elements
     * @return the result of the addition
     */
    @Override
    @NonNull
    public GroupElement batchAdd(@NonNull final Collection<GroupElement> elements) {
        BigInteger sum = BigInteger.ZERO;
        for (final GroupElement element : elements) {
            sum = sum.add(((NaiveGroupElement) element).value()).mod(BigInteger.valueOf(23));
        }
        return new NaiveGroupElement(this, sum);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement fromBytes(@NonNull final byte[] bytes) {
        final BigInteger value = new BigInteger(bytes).mod(BigInteger.valueOf(23));
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
