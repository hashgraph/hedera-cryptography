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
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.Objects;

/**
 * A naive implementation of the FieldElement interface for testing purposes.
 * This implementation provides basic arithmetic operations on field elements.
 */
public class NaiveFieldElement implements FieldElement {
    /**
     * The prime modulus used for field operations.
     */
    public static final BigInteger PRIME_MODULUS = BigInteger.valueOf(23);

    private final Field field;
    private final BigInteger value;

    /**
     * Constructs a NaiveFieldElement with the specified field and value.
     * The value is reduced modulo the prime modulus to ensure it fits within the finite field defined by the group.
     *
     * @param field the field associated with this field element
     * @param value the value of this field element
     */
    public NaiveFieldElement(@NonNull final Field field, @NonNull final BigInteger value) {
        Objects.requireNonNull(value, "value must not be null");
        this.field = Objects.requireNonNull(field, "field must not be null");
        this.value = value.mod(PRIME_MODULUS);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public Field field() {
        return field;
    }

    /**
     * Adds this field element to another field element.
     * The result is reduced modulo the prime modulus.
     *
     * @param other the other field element
     * @return the result of the addition
     */
    @Override
    @NonNull
    public FieldElement add(@NonNull final FieldElement other) {
        return new NaiveFieldElement(field, this.value.add(other.toBigInteger()));
    }

    /**
     * Subtracts another field element from this field element.
     * The result is reduced modulo the prime modulus.
     *
     * @param other the other field element
     * @return the result of the subtraction
     */
    @Override
    @NonNull
    public FieldElement subtract(@NonNull final FieldElement other) {
        return new NaiveFieldElement(field, this.value.subtract(other.toBigInteger()));
    }

    /**
     * Multiplies this field element by another field element.
     * The result is reduced modulo the prime modulus.
     *
     * @param other the other field element
     * @return the result of the multiplication
     */
    @Override
    @NonNull
    public FieldElement multiply(@NonNull final FieldElement other) {
        return new NaiveFieldElement(field, this.value.multiply(other.toBigInteger()));
    }

    /**
     * Raises this field element to the power of the specified exponent.
     * The result is reduced modulo the prime modulus.
     *
     * @param exponent the exponent
     * @return the result of the exponentiation
     */
    @Override
    @NonNull
    public FieldElement power(final long exponent) {
        return new NaiveFieldElement(field, this.value.pow((int) exponent));
    }

    /**
     * Computes the multiplicative inverse of this field element.
     * The result is reduced modulo the prime modulus.
     *
     * @return the multiplicative inverse
     */
    @Override
    @NonNull
    public FieldElement inverse() {
        return new NaiveFieldElement(field, this.value.modInverse(PRIME_MODULUS));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public BigInteger toBigInteger() {
        return value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public byte[] toBytes() {
        return value.toByteArray();
    }

    @NonNull
    @Override
    public byte[] toByteArray() {
        return value.toByteArray();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "NaiveFieldElement{" + "value=" + value + '}';
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final NaiveFieldElement that = (NaiveFieldElement) o;
        return Objects.equals(value, that.value);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
