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

import static com.hedera.platform.bls.impl.BLS12381Bindings.SUCCESS;
import static com.hedera.platform.bls.impl.BLS12381Bindings.checkScalarValidity;
import static com.hedera.platform.bls.impl.BLS12381Bindings.scalarAdd;
import static com.hedera.platform.bls.impl.BLS12381Bindings.scalarDivide;
import static com.hedera.platform.bls.impl.BLS12381Bindings.scalarEquals;
import static com.hedera.platform.bls.impl.BLS12381Bindings.scalarMultiply;
import static com.hedera.platform.bls.impl.BLS12381Bindings.scalarPower;
import static com.hedera.platform.bls.impl.BLS12381Bindings.scalarSubtract;

import com.hedera.platform.bls.api.Field;
import com.hedera.platform.bls.api.FieldElement;
import java.math.BigInteger;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/** An element in {@link BLS12381Field} */
public class BLS12381FieldElement implements FieldElement {
    /** The field the element is in */
    private static final BLS12381Field FIELD = BLS12381Field.getInstance();

    /** The byte representation of the element */
    private final byte[] fieldElement;

    /**
     * Package private constructor
     *
     * @param fieldElement an array of bytes representing this field element
     */
    public BLS12381FieldElement(final byte[] fieldElement) {
        if (fieldElement == null) {
            throw new IllegalArgumentException("fieldElement parameter must not be null");
        }

        this.fieldElement = fieldElement;
    }

    /** {@inheritDoc} */
    @Override
    public Field field() {
        return FIELD;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] toBytes() {
        return fieldElement;
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement add(final FieldElement other) {
        if (!(other instanceof final BLS12381FieldElement otherElement)) {
            throw new IllegalArgumentException("other must be a valid BLS12381FieldElement");
        }

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        final int errorCode = scalarAdd(this, otherElement, output);
        if (errorCode != SUCCESS) {
            throw new BLS12381Exception("scalarAdd", errorCode);
        }

        return new BLS12381FieldElement(output);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement subtract(final FieldElement other) {
        if (!(other instanceof final BLS12381FieldElement otherElement)) {
            throw new IllegalArgumentException("other must be a valid BLS12381FieldElement");
        }

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        final int errorCode = scalarSubtract(this, otherElement, output);
        if (errorCode != SUCCESS) {
            throw new BLS12381Exception("scalarSubtract", errorCode);
        }

        return new BLS12381FieldElement(output);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement multiply(final FieldElement other) {
        if (!(other instanceof final BLS12381FieldElement otherElement)) {
            throw new IllegalArgumentException("other must be a valid BLS12381FieldElement");
        }

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        final int errorCode = scalarMultiply(this, otherElement, output);
        if (errorCode != SUCCESS) {
            throw new BLS12381Exception("scalarMultiply", errorCode);
        }

        return new BLS12381FieldElement(output);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement divide(final FieldElement other) {
        if (!(other instanceof final BLS12381FieldElement otherElement)) {
            throw new IllegalArgumentException("other must be a valid BLS12381FieldElement");
        }

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        final int errorCode = scalarDivide(this, otherElement, output);
        if (errorCode != SUCCESS) {
            throw new BLS12381Exception("scalarDivide", errorCode);
        }

        return new BLS12381FieldElement(output);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement power(final BigInteger exponent) {
        if (exponent == null) {
            throw new IllegalArgumentException("exponent cannot be null");
        }

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        final int errorCode = scalarPower(this, exponent.toByteArray(), output);
        if (errorCode != SUCCESS) {
            throw new BLS12381Exception("scalarPower", errorCode);
        }

        return new BLS12381FieldElement(output);
    }

    /** {@inheritDoc} */
    @Override
    public boolean isValid() {
        return fieldElement.length == FIELD.getElementSize() && checkScalarValidity(this);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null) {
            return false;
        }

        if (!(o instanceof final BLS12381FieldElement element)) {
            return false;
        }

        return scalarEquals(this, element);
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(fieldElement).append(FIELD).build();
    }
}
