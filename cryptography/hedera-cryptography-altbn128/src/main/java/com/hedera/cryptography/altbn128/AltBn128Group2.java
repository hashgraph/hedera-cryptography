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
import com.hedera.cryptography.altbn128.facade.Group2;
import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * The implementation of a {@link Group2}
 * for {@link com.hedera.cryptography.pairings.api.curves.KnownCurves#ALT_BN128}
 */
public class AltBn128Group2 implements Group {
    private final Group2 facade;

    /**
     * Creates an instance of a {@link Group2} for this implementation.
     */
    public AltBn128Group2() {
        this.facade = new Group2(
                ArkBn254Adapter.getInstance(), ArkBn254Adapter.getInstance().fieldElementsSize());
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public BilinearPairing getPairing() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement generator() {
        return new AltBn128Group2Element(this, facade.generator(), facade);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement zero() {
        return new AltBn128Group2Element(this, facade.zero(), facade);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement random(@NonNull final byte[] seed) {
        return new AltBn128Group2Element(this, facade.fromSeed(seed), facade);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement fromHash(@NonNull final byte[] input) {
        return new AltBn128Group2Element(this, facade.fromSeed(HashUtils.computeSha256(input)), facade);
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
        byte[][] all = new byte[elems.size()][];
        for (int i = 0; i < elems.size(); i++) {
            all[i] = elems.get(i).getInnerRepresentation();
        }
        return new AltBn128Group2Element(this, facade.batchAdd(all), facade);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement fromBytes(@NonNull final byte[] bytes) {
        return new AltBn128Group2Element(this, facade.fromAffineSerialization(bytes), facade);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getCompressedSize() {
        return facade.size();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getUncompressedSize() {
        return facade.size();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getSeedSize() {
        return facade.randomSeedSize();
    }
}
