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
import com.hedera.cryptography.altbn128.common.HashUtils;
import com.hedera.cryptography.altbn128.facade.Group2Facade;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * The implementation of the second {@link Group} of {@link com.hedera.cryptography.pairings.api.curves.KnownCurves#ALT_BN128}
 */
public class AltBn128Group2 implements Group {
    private final Group2Facade facade;

    /**
     * Creates an instance of a {@link Group2Facade} for this implementation.
     */
    public AltBn128Group2() {
        this.facade = new Group2Facade(
                ArkBn254Adapter.getInstance(), ArkBn254Adapter.getInstance().fieldElementsSize());
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public PairingFriendlyCurve getPairingFriendlyCurve() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement generator() {
        return new AltBn128Group2Element(this, facade.generator());
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement zero() {
        return new AltBn128Group2Element(this, facade.zero());
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement random(@NonNull final byte[] seed) {
        return new AltBn128Group2Element(this, facade.fromSeed(seed));
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement fromHash(@NonNull final byte[] input) {
        return new AltBn128Group2Element(this, facade.fromSeed(HashUtils.computeSha256(input)));
    }

    /**
     * {@inheritDoc}
     * @throws IllegalArgumentException if any of the elements is null or not an instance of {@link AltBn128Group2Element}
     */
    @NonNull
    @Override
    public GroupElement batchAdd(@NonNull final Collection<GroupElement> elements) {
        Objects.requireNonNull(elements, "elements must not be null");
        if (elements.stream().anyMatch(e -> !AltBn128Group2Element.class.isAssignableFrom(e.getClass()))) {
            throw new IllegalArgumentException("elements must implement AltBn128Group2Element");
        }
        List<AltBn128Group2Element> elems =
                elements.stream().map(AltBn128Group2Element.class::cast).toList();
        final byte[][] all = new byte[elems.size()][];
        for (int i = 0; i < elems.size(); i++) {
            all[i] = elems.get(i).getRepresentation();
        }
        return new AltBn128Group2Element(this, facade.batchAdd(all));
    }

    /**
     * Multiplies a list of scalar values for the generator point of the group
     *
     *
     * @param elements the scalar elements to multiply the generator
     * @return same size list of points that are the generator point of this curve times the scalar in the same index
     * @throws NullPointerException if the elements is null
     * @throws IllegalArgumentException if the bytes are n
     * @throws AltBn128Exception in case of error.
     *
     */
    public List<GroupElement> batchMultiply(@NonNull final Collection<FieldElement> elements) {
        Objects.requireNonNull(elements, "elements must not be null");
        if (elements.stream().anyMatch(e -> !AltBn128FieldElement.class.isAssignableFrom(e.getClass()))) {
            throw new IllegalArgumentException("elements must implement AltBn128Group2Element");
        }
        List<AltBn128FieldElement> elems =
                elements.stream().map(AltBn128FieldElement.class::cast).toList();
        final byte[][] all = new byte[elems.size()][];
        for (int i = 0; i < elems.size(); i++) {
            all[i] = elems.get(i).getRepresentation();
        }
        final byte[][] g2Elements = facade.batchMultiply(all);

        return Arrays.stream(g2Elements)
                .map(rep -> (GroupElement) new AltBn128Group2Element(this, rep))
                .toList();
    }

    /**
     * Creates a group element from its serialized encoding, validating if the point is in the curve.
     *
     * @throws NullPointerException if the bytes is null
     * @throws IllegalArgumentException if the bytes is of invalid size or the point does not belong to the curve
     * @throws AltBn128Exception in case of error.
     */
    @NonNull
    @Override
    public GroupElement fromBytes(@NonNull final byte[] bytes) {
        return new AltBn128Group2Element(this, facade.fromBytes(bytes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int seedSize() {
        return facade.randomSeedSize();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int elementSize() {
        return facade.size();
    }
}
