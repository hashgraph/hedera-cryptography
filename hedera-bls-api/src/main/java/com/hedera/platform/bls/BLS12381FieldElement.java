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
package com.hedera.platform.bls;

import java.math.BigInteger;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/** An element in {@link BLS12381Field} */
public class BLS12381FieldElement implements FieldElement {
    /** The byte representation of the element */
    private final byte[] fieldElement;

    /** The field the element is in */
    private final BLS12381Field field;

    /**
     * Package private constructor
     *
     * @param fieldElement an array of bytes representing this field element
     * @param field the field this element is in
     */
    public BLS12381FieldElement(final byte[] fieldElement, final BLS12381Field field) {
        if (fieldElement == null || field == null) {
            throw new IllegalArgumentException("all arguments must be valid");
        }

        this.fieldElement = fieldElement;
        this.field = field;
    }

    /** {@inheritDoc} */
    @Override
    public Field getField() {
        return field;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] toBytes() {
        return fieldElement;
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement add(final FieldElement other) {
        if (other == null) {
            throw new IllegalArgumentException("other cannot be null");
        }

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.scalarAdd(this, (BLS12381FieldElement) other, output))
                != 0) {
            throw new BLS12381Exception("scalarAdd", errorCode);
        }

        return new BLS12381FieldElement(output, field);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement subtract(final FieldElement other) {
        if (other == null) {
            throw new IllegalArgumentException("other cannot be null");
        }

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        final int errorCode;
        if ((errorCode =
                        BLS12381Bindings.scalarSubtract(this, (BLS12381FieldElement) other, output))
                != 0) {
            throw new BLS12381Exception("scalarSubtract", errorCode);
        }

        return new BLS12381FieldElement(output, field);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement multiply(final FieldElement other) {
        if (other == null) {
            throw new IllegalArgumentException("other cannot be null");
        }

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        final int errorCode;
        if ((errorCode =
                        BLS12381Bindings.scalarMultiply(this, (BLS12381FieldElement) other, output))
                != 0) {
            throw new BLS12381Exception("scalarMultiply", errorCode);
        }

        return new BLS12381FieldElement(output, field);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement divide(final FieldElement other) {
        if (other == null) {
            throw new IllegalArgumentException("other cannot be null");
        }

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.scalarDivide(this, (BLS12381FieldElement) other, output))
                != 0) {
            throw new BLS12381Exception("scalarDivide", errorCode);
        }

        return new BLS12381FieldElement(output, field);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement power(final BigInteger exponent) {
        if (exponent == null) {
            throw new IllegalArgumentException("exponent cannot be null");
        }

        final byte[] output = new byte[BLS12381Field.ELEMENT_BYTE_SIZE];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.scalarPower(this, exponent.toByteArray(), output)) != 0) {
            throw new BLS12381Exception("scalarPower", errorCode);
        }

        return new BLS12381FieldElement(output, field);
    }

    /** {@inheritDoc} */
    @Override
    public boolean isValid() {
        return fieldElement.length == field.getElementSize()
                && BLS12381Bindings.checkScalarValidity(this);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null) {
            return false;
        }

        if (o instanceof BLS12381FieldElement element) {
            return field.equals(element.field) && BLS12381Bindings.scalarEquals(this, element);
        }

        return false;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(fieldElement).append(field).build();
    }
}
