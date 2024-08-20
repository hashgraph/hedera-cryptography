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
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.Objects;

/**
 * The implementation of a {@link FieldElement}
 * for {@link com.hedera.cryptography.pairings.api.curves.KnownCurves#ALT_BN128}
 */
public class AltBn128FieldElement implements FieldElement {

    private final AltBn128Field field;
    private final byte[] representation;
    private final FieldElements facade;

    /**
     * Creates a new {@link FieldElement}.
     * @param representation the byte array representation
     * @param field the {@link Field} that this instance will be an element of.
     */
    public AltBn128FieldElement(@NonNull final byte[] representation, @NonNull final AltBn128Field field) {
        this(representation, field, new FieldElements(ArkBn254Adapter.getInstance()));
    }

    /**
     * Creates a new {@link FieldElement}.
     * @param representation the byte array representation
     * @param field the {@link Field} that this instance will be an element of.
     * @param facade the class implementing the high-level operations to handle FieldElements representations
     */
    AltBn128FieldElement(
            @NonNull final byte[] representation,
            @NonNull final AltBn128Field field,
            @NonNull final FieldElements facade) {
        this.representation = Objects.requireNonNull(representation, "representation must not be null");
        this.field = field;
        this.facade = facade;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public Field getField() {
        return this.field;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public FieldElement add(@NonNull final FieldElement other) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public FieldElement subtract(@NonNull final FieldElement other) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public FieldElement multiply(@NonNull final FieldElement other) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public FieldElement power(@NonNull final BigInteger exponent) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Returns the field element as a {@link BigInteger} from this element's byte array representation.
     * The byte array representation in this implementation is in little-endian format.
     * Since {@code BigInteger} expects a big-endian byte array by default, the result reflects the interpretation of the little-endian
     * array under big-endian assumptions.
     * Therefore, if the input byte array in little-endian is:
     * <pre>
     *   [0x01, 0x00, 0x00, 0x00, ..., 0x00]
     * </pre>
     * That represent the number 1 in little-endian format, the {@link BigInteger} returned won't be the same, as
     * the {@code BigInteger} that represents the number 1.
     *
     * @return a {@link BigInteger} reflecting the direct interpretation of the internal little-endian byte array as big-endian
     */
    @NonNull
    @Override
    public BigInteger toBigInteger() {
        return new BigInteger(representation);
    }

    /**
     * Returns the byte array representation of the field element
     * The representation is in {@link java.nio.ByteOrder#LITTLE_ENDIAN}
     * @return the byte array representation of the field element
     */
    @NonNull
    @Override
    public byte[] toBytes() {
        return representation.clone();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof AltBn128FieldElement)) return false;
        if (this.field != ((AltBn128FieldElement) obj).field) return false;
        if (this.representation.length != ((AltBn128FieldElement) obj).representation.length) return false;

        return facade.equals(this.representation, ((AltBn128FieldElement) obj).representation);
    }

    // TODO: what about hashCode? should we rely on the hashCode of the array? seems sensible.
}
