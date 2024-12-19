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

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.ValidationUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * A naive implementation of the GroupElement interface for testing purposes. This implementation provides basic
 * arithmetic operations on group elements.
 */
public final class NaiveGroupElement implements GroupElement {
    private final Group group;
    final NaiveFieldElement value;

    /**
     * Constructs a NaiveGroupElement with the specified group and value.
     *
     * @param group the group associated with this group element
     * @param value the value of this group element
     */
    public NaiveGroupElement(@NonNull final Group group, NaiveFieldElement value) {
        this.group = Objects.requireNonNull(group, "group must not be null");
        this.value = value;
    }

    /**
     * Constructs a NaiveGroupElement with the specified group and value.
     *
     * @param group the group associated with this group element
     * @param value the value of this group element
     */
    public NaiveGroupElement(@NonNull final Group group, @NonNull final Field field, final int value) {
        this.group = Objects.requireNonNull(group, "group must not be null");
        this.value = new NaiveFieldElement(field, value);
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

    @NonNull
    @Override
    public GroupElement multiply(final long other) {
        return this.multiply(this.group().field().fromLong(other));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement multiply(@NonNull final FieldElement other) {
        var value = ValidationUtils.expectOrThrow(NaiveFieldElement.class, other);
        return new NaiveGroupElement(group, (NaiveFieldElement) this.value.multiply(value));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement add(@NonNull final GroupElement other) {
        Objects.requireNonNull(other, "other must not be null");
        var value = ValidationUtils.expectOrThrow(NaiveGroupElement.class, other).value;
        return new NaiveGroupElement(group, (NaiveFieldElement) this.value.add(value));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public byte[] toBytes() {
        return value.toBytes();
    }

    @NonNull
    @Override
    public List<BigInteger> getXCoordinate() {
        return List.of(value.toBigInteger());
    }

    @NonNull
    @Override
    public List<BigInteger> getYCoordinate() {
        return List.of(BigInteger.ZERO);
    }

    @Override
    public boolean isZero() {
        return false;
    }

    @Override
    public boolean isYNegative() {
        return false;
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
        return ValidationUtils.expectOrThrow(NaiveGroupElement.class, otherElement)
                .getGroup()
                .equals(this.group);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isOppositeGroup(@NonNull final GroupElement otherElement) {
        return ValidationUtils.expectOrThrow(NaiveGroupElement.class, otherElement)
                .group()
                .getOppositeGroup()
                .equals(group.getOppositeGroup());
    }

    @NonNull
    public Group group() {
        return group;
    }

    public int value() {
        return value.value;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null || obj.getClass() != this.getClass()) {
            return false;
        }
        var that = (NaiveGroupElement) obj;
        return Objects.equals(this.value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group, value);
    }

    @Override
    public String toString() {
        return "NaiveGroupElement[" + "group=" + group + ", " + "value=" + value + ']';
    }
}
