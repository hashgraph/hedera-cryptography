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
import com.hedera.cryptography.pairings.api.PairingsException;
import com.hedera.cryptography.pairings.test.fixtures.Utils;
import com.hedera.cryptography.utils.ByteArrayUtils;
import com.hedera.cryptography.utils.ValidationUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.stream.IntStream;

/**
 * A naive implementation of the FieldElement interface for testing purposes.
 * This implementation provides basic arithmetic operations on field elements.
 */
public class NaiveFieldElement implements FieldElement {
    /**
     * The prime modulus used for field operations.
     */
    public static final int PRIME_MODULUS = 23;

    private final Field field;
    final int value;

    /**
     * Constructs a NaiveFieldElement with the specified field and value.
     * The value is reduced modulo the prime modulus to ensure it fits within the finite field defined by the group.
     *
     * @param field the field associated with this field element
     * @param value the value of this field element
     */
    public NaiveFieldElement(@NonNull final Field field, final long value) {
        this.field = Objects.requireNonNull(field, "field must not be null");
        this.value = value < 0 ? PRIME_MODULUS - (int) ((-value) % PRIME_MODULUS) : (int) (value % PRIME_MODULUS);

        var nums = new HashSet<>(IntStream.range(0, PRIME_MODULUS).boxed().toList());
        Map<Integer, Integer> inverses = new HashMap<>();
        for (int i = 0; i < PRIME_MODULUS; i++) {
            for (Integer num : nums) {
                if ((value * i) % PRIME_MODULUS == 1) {
                    inverses.put(i, num);
                    break;
                }
            }
            nums.remove(inverses.get(i));
        }
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
        return new NaiveFieldElement(field, this.value + ((NaiveFieldElement) other).value);
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

        var value = ValidationUtils.expectOrThrow(NaiveFieldElement.class, other).value;
        return new NaiveFieldElement(field, this.value - value);
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
        var val = ValidationUtils.expectOrThrow(NaiveFieldElement.class, other).value;
        return new NaiveFieldElement(field, this.value * val);
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
        long result = Utils.intPow(value, exponent);
        return new NaiveFieldElement(field, result);
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
        if (value == 0) throw new PairingsException("Non invertible");

        throw new PairingsException("Non invertible");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public BigInteger toBigInteger() {
        return BigInteger.valueOf(value);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public byte[] toBytes() {
        return ByteArrayUtils.toByteArray(value);
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
