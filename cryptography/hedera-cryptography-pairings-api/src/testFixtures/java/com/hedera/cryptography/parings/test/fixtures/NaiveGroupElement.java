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

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * A naive implementation of the GroupElement interface for testing purposes.
 * This implementation provides basic arithmetic operations on group elements.
 */
public record NaiveGroupElement(@NonNull Group group, @NonNull BigInteger value) implements GroupElement {

    /**
     * Constructs a NaiveGroupElement with the specified group and value.
     *
     * @param group the group associated with this group element
     * @param value the value of this group element
     */
    public NaiveGroupElement(@NonNull final Group group, @NonNull final BigInteger value) {
        this.group = group;
        this.value = value.mod(BigInteger.valueOf(23)); // Modulus for the finite field
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int size() {
        return group.elementSize();
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public Group getGroup() {
        return group;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement multiply(@NonNull final FieldElement other) {
        final BigInteger newValue = value.multiply(other.toBigInteger()).mod(BigInteger.valueOf(23));
        return new NaiveGroupElement(group, newValue);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement add(@NonNull final GroupElement other) {
        final BigInteger newValue =
                value.add(((NaiveGroupElement) other).value()).mod(BigInteger.valueOf(23));
        return new NaiveGroupElement(group, newValue);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public byte[] toBytes() {
        final byte[] bytes = value.toByteArray();

        // Ensure the byte array is exactly 32 bytes
        if (bytes.length == EXAMPLE_SIZE) {
            return bytes;
        } else if (bytes.length < EXAMPLE_SIZE) {
            final byte[] paddedBytes = new byte[EXAMPLE_SIZE];
            System.arraycopy(bytes, 0, paddedBytes, EXAMPLE_SIZE - bytes.length, bytes.length);
            return paddedBytes;
        } else {
            return Arrays.copyOfRange(bytes, bytes.length - EXAMPLE_SIZE, bytes.length);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement copy() {
        return new NaiveGroupElement(group, value);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isSameGroup(@NonNull final GroupElement otherElement) {
        return otherElement.getGroup().equals(this.group);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isOppositeGroup(@NonNull final GroupElement otherElement) {
        return group.getOppositeGroup().equals(otherElement.getGroup());
    }
}
