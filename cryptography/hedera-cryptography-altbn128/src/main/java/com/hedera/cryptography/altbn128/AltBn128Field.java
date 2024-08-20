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
import com.hedera.cryptography.altbn128.facade.FieldElements;
import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;

/**
 * The implementation of a {@link Field}
 * for {@link com.hedera.cryptography.pairings.api.curves.KnownCurves#ALT_BN128}
 */
public class AltBn128Field implements Field {
    private final Group group;
    private final FieldElements facade;

    /**
     * Creates an instance of a {@link Field} for this implementation.
     * @param group The group this field belongs too
     * @throws NullPointerException if group is null
     */
    public AltBn128Field(@NonNull final Group group) {
        this.group = Objects.requireNonNull(group, "Group must not be null");
        this.facade = new FieldElements(ArkBn254Adapter.getInstance(), 0);
    }

    @NonNull
    @Override
    public FieldElement elementFromLong(final long inputLong) {
        final byte[] representation = facade.fromLong(inputLong);
        return new AltBn128FieldElement(representation, this);
    }

    @NonNull
    @Override
    public FieldElement randomElement(@NonNull final byte[] seed) {
        final byte[] representation = facade.fromRandomSeed(seed);
        return new AltBn128FieldElement(representation, this);
    }

    @NonNull
    @Override
    public FieldElement elementFromBytes(@NonNull final byte[] representation) {
        return new AltBn128FieldElement(facade.fromBytes(representation), this);
    }

    /**
     * Return a FieldElement of value 0
     * @return a FieldElement of value 0
     */
    @NonNull
    public FieldElement zero() {
        return new AltBn128FieldElement(facade.zero(), this);
    }

    /**
     * Return a FieldElement of value 1
     * @return a FieldElement of value 1
     */
    @NonNull
    public FieldElement one() {
        return new AltBn128FieldElement(facade.one(), this);
    }

    /**
     * Return the occupied size in bytes of this field's FieldElements.
     * @return the occupied size in bytes of this field's FieldElements
     */
    @Override
    public int getElementSize() {
        return facade.size();
    }

    /**
     * Return the size in bytes for the random seed.
     * @return the size in bytes for the random seed.
     */
    @Override
    public int getSeedSize() {
        return facade.randomSeedSize();
    }

    @NonNull
    @Override
    public BilinearPairing getPairing() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Returns  The group this field belongs too.
     * @return  The group this field belongs too
     */
    // QQ @rohit: Is it the case that for this curve, we need to associate the fields to each group, and they are
    // different than bls-381
    @NonNull
    public Group getGroup() {
        return group;
    }
}
