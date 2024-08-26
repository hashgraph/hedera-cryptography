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

package com.hedera.cryptography.altbn128;

import com.hedera.cryptography.altbn128.adapter.jni.ArkBn254Adapter;
import com.hedera.cryptography.altbn128.facade.Group2Facade;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.Arrays;
import java.util.Objects;

/**
 * The implementation of a {@link GroupElement}
 * for {@link com.hedera.cryptography.pairings.api.curves.KnownCurves#ALT_BN128}
 */
public class AltBn128Group2Element implements GroupElement {
    private final byte[] innerRepresentation;
    private final Group2Facade facade;
    private final Group group;

    /**
     * Creates a new instance
     * @param group the group this element belongs to
     * @param innerRepresentation the byte array representation of this element
     */
    public AltBn128Group2Element(@NonNull Group group, @NonNull final byte[] innerRepresentation) {
        this.group = Objects.requireNonNull(group, "group must not be null");
        this.innerRepresentation = Objects.requireNonNull(innerRepresentation, "innerRepresentation must not be null");
        this.facade = new Group2Facade(
                ArkBn254Adapter.getInstance(), ArkBn254Adapter.getInstance().fieldElementsSize());
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
    @NonNull
    @Override
    public GroupElement multiply(@NonNull final FieldElement other) {
        Objects.requireNonNull(other, "other must not be null");
        return new AltBn128Group2Element(group, facade.scalarMul(this.innerRepresentation, other.toBytes()));
    }

    /**
     * {@inheritDoc}
     * @throws IllegalArgumentException if other is not instance of {@link AltBn128Group2Element}
     */
    @NonNull
    @Override
    public GroupElement add(@NonNull final GroupElement other) {
        return new AltBn128Group2Element(
                group, facade.add(this.innerRepresentation, asSubclassOrThrow(other).innerRepresentation));
    }

    @NonNull
    private AltBn128Group2Element asSubclassOrThrow(final @Nullable GroupElement other) {
        Objects.requireNonNull(other, "other must not be null");
        if (!(other instanceof AltBn128Group2Element)) {
            throw new IllegalArgumentException("Not the correct group element");
        }
        return (AltBn128Group2Element) other;
    }

    /**
     * {@inheritDoc}
     * @deprecated
     */
    @Deprecated
    @NonNull
    @Override
    public GroupElement compress() {
        return this.copy();
    }

    /**
     * {@inheritDoc}
     * @deprecated
     */
    @Deprecated
    @Override
    public boolean isCompressed() {
        return false;
    }

    /**
     * {@inheritDoc}
     * @deprecated
     */
    @Deprecated
    @NonNull
    @Override
    public GroupElement copy() {
        return new AltBn128Group2Element(group, Arrays.copyOf(innerRepresentation, innerRepresentation.length));
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public byte[] toBytes() {
        return Arrays.copyOf(this.innerRepresentation, innerRepresentation.length);
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof AltBn128Group2Element)) {
            return false;
        }
        if (this == obj) {
            return true;
        }

        return facade.equals(this.innerRepresentation, ((AltBn128Group2Element) obj).innerRepresentation);
    }

    /**
     * Returns the internal projective representation of this point.
     * @return the internal projective representation of this point
     */
    byte[] getInnerRepresentation() {
        return innerRepresentation;
    }
}
