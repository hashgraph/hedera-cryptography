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

import com.hedera.platform.bls.api.FieldElement;
import com.hedera.platform.bls.api.Group;
import com.hedera.platform.bls.api.GroupElement;
import java.util.Arrays;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/** An element in Group 2 of the BLS 12-381 curve family */
public class BLS12381Group2Element implements GroupElement {
    /** The group this element is part of */
    private static final BLS12381Group2 GROUP = BLS12381Group2.getInstance();

    /** The bytes representation of the element */
    private byte[] groupElement;

    /** True if the {@link #groupElement} bytes are in a compressed form, otherwise false */
    private boolean compressed;

    /**
     * Package private constructor. This is used by {@link BLS12381Group2}, but shouldn't be called
     * directly by anyone else
     *
     * @param groupElement a byte array representing this group element
     */
    BLS12381Group2Element(final byte[] groupElement) {
        if (groupElement == null) {
            throw new IllegalArgumentException("groupElement parameter must not be null");
        }

        this.groupElement = groupElement;
        this.compressed = groupElement.length == GROUP.getCompressedSize();
    }

    /**
     * Package private copy constructor
     *
     * @param other the object being copied
     */
    BLS12381Group2Element(final BLS12381Group2Element other) {
        if (other == null) {
            throw new IllegalArgumentException("other cannot be null");
        }

        this.groupElement = Arrays.copyOf(other.groupElement, other.groupElement.length);
        this.compressed = other.compressed;
    }

    /** {@inheritDoc} */
    @Override
    public Group group() {
        return GROUP;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] toBytes() {
        return groupElement;
    }

    /** {@inheritDoc} */
    @Override
    public GroupElement power(final FieldElement exponent) {
        if (!(exponent instanceof final BLS12381FieldElement exponentElement)) {
            throw new IllegalArgumentException("exponent must be a valid BLS12381FieldElement");
        }

        final byte[] output = new byte[GROUP.getUncompressedSize()];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g2PowZn(this, exponentElement, output)) != 0) {
            throw new BLS12381Exception("g2PowZn", errorCode);
        }

        return new BLS12381Group2Element(output);
    }

    /** {@inheritDoc} */
    @Override
    public GroupElement multiply(final GroupElement other) {
        if (!(other instanceof final BLS12381Group2Element otherElement)) {
            throw new IllegalArgumentException("other must be a valid BLS12381Group2Element");
        }

        final byte[] output = new byte[GROUP.getUncompressedSize()];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g2Multiply(this, otherElement, output)) != 0) {
            throw new BLS12381Exception("g2Multiply", errorCode);
        }

        return new BLS12381Group2Element(output);
    }

    /** {@inheritDoc} */
    @Override
    public GroupElement divide(final GroupElement other) {
        if (!(other instanceof final BLS12381Group2Element otherElement)) {
            throw new IllegalArgumentException("other must be a valid BLS12381Group2Element");
        }

        final byte[] output = new byte[GROUP.getUncompressedSize()];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g2Divide(this, otherElement, output)) != 0) {
            throw new BLS12381Exception("g2Divide", errorCode);
        }

        return new BLS12381Group2Element(output);
    }

    /** {@inheritDoc} */
    @Override
    public GroupElement compress() {
        // Already compressed, no need to do anything
        if (compressed) {
            return this;
        }

        byte[] newGroupElement = new byte[GROUP.getCompressedSize()];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.g2Compress(this, newGroupElement)) != 0) {
            throw new BLS12381Exception("g2Compress", errorCode);
        }

        groupElement = newGroupElement;
        compressed = true;

        return this;
    }

    /** {@inheritDoc} */
    @Override
    public boolean isCompressed() {
        return compressed;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null) {
            return false;
        }

        if (!(o instanceof final BLS12381Group2Element element)) {
            return false;
        }

        return BLS12381Bindings.g2ElementEquals(this, element);
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(groupElement).append(GROUP).append(compressed).build();
    }

    @Override
    public String toString() {
        return Arrays.toString(groupElement);
    }

    /** {@inheritDoc} */
    @Override
    public BLS12381Group2Element copy() {
        return new BLS12381Group2Element(this);
    }

    /** {@inheritDoc} */
    @Override
    public boolean isValid() {
        return (groupElement.length == GROUP.getCompressedSize()
                        || groupElement.length == GROUP.getUncompressedSize())
                && BLS12381Bindings.checkG2Validity(this);
    }
}
