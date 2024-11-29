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

import static com.hedera.cryptography.utils.ValidationUtils.expectOrThrow;

import com.hedera.cryptography.altbn128.adapter.jni.ArkBn254Adapter;
import com.hedera.cryptography.altbn128.facade.FieldFacade;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.utils.ByteArrayUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * The implementation of a {@link Field}
 * for {@link com.hedera.cryptography.pairings.api.curves.KnownCurves#ALT_BN128}
 */
public class AltBn128Field implements Field {
    private final FieldFacade facade;

    /**
     * Creates an instance of a {@link Field} for this implementation.
     */
    public AltBn128Field() {
        this.facade = new FieldFacade(ArkBn254Adapter.getInstance());
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public FieldElement fromLong(final long inputLong) {
        final byte[] representation = facade.fromLong(inputLong);
        return new AltBn128FieldElement(representation, this);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public FieldElement random(@NonNull final byte[] seed) {
        final byte[] representation = facade.fromRandomSeed(seed);
        return new AltBn128FieldElement(representation, this);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public FieldElement fromBytes(@NonNull final byte[] representation) {
        return new AltBn128FieldElement(facade.fromBytes(representation), this);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public FieldElement fromBigInteger(@NonNull final BigInteger bigInteger) {
        if (Objects.requireNonNull(bigInteger, "bigInteger must not be null").signum() == -1) {
            throw new IllegalArgumentException("bigInteger cannot be negative");
        }
        return new AltBn128FieldElement(
                facade.fromBytes(ByteArrayUtils.toLittleEndianBytes(bigInteger, facade.size())), this);
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
    public int elementSize() {
        return facade.size();
    }

    /**
     * Return the size in bytes for the random seed.
     * @return the size in bytes for the random seed.
     */
    @Override
    public int seedSize() {
        return facade.randomSeedSize();
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public FieldElement add(@NonNull final List<FieldElement> scalars) {
        byte[][] params = Objects.requireNonNull(scalars, "scalars must not be null").stream()
                .map(thizz -> expectOrThrow(AltBn128FieldElement.class, thizz))
                .map(AltBn128FieldElement::getRepresentation)
                .toArray(byte[][]::new);

        return new AltBn128FieldElement(facade.batchAdd(params), this);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public FieldElement multiply(@NonNull final List<Integer> scalars) {
        return new AltBn128FieldElement(
                facade.batchMultiply(scalars.stream().mapToLong(Long::valueOf).toArray()), this);
    }

    @NonNull
    @Override
    public PairingFriendlyCurve getPairingFriendlyCurve() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
