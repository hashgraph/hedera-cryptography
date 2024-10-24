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

package com.hedera.cryptography.tss.extensions;

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;

/**
 * A polynomial, represented as a list of coefficients where each {@code coefficients[i]} corresponds to the coefficient for {@code x^i}.
 * @implNote it is responsibility of the user that the {@link FieldElement} instances are compatible with each-other.
 *  Otherwise, it might fail on the {@link #evaluate(long)} method depending on the implementation of {@link FieldElement}
 * @param coefficients the coefficients of the polynomial.
 */
public record Polynomial(@NonNull List<FieldElement> coefficients) {

    /**
     * Creates a polynomial that is represented as a list of {@link FieldElement} coefficients,
     *  where {@code coefficients[i]} corresponds to the coefficient for {@code x^i}.
     * @param coefficients the list of coefficients
     * @throws NullPointerException if {@code coefficients} parameter is null
     * @throws IllegalArgumentException if {@code coefficients} parameter is empty
     */
    public Polynomial {
        if (Objects.requireNonNull(coefficients).isEmpty())
            throw new IllegalArgumentException("coefficients cannot be empty");
    }

    /**
     * Returns the degree of the polynomial.
     *
     * @return the degree of the polynomial.
     */
    public int degree() {
        return coefficients.size() - 1;
    }

    /**
     * Creates a random degree d polynomial with a fixed point at x = 0.
     * The polynomial generated here has d+1 number of coefficients: {@code a_0, a_1, ..., a_d} such that: <br/>
     * {@code p(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_d * x^d}
     *
     * @param random    a source of randomness
     * @param fixedValue the fixedValue to embed in the polynomial
     * @param degree    the degree of the polynomial.
     * @return a random polynomial of the given degree, with the given fixedValue embedded at x = 0
     * @throws NullPointerException if any of the parameters is null
     * @throws IllegalArgumentException if the degree is not a positive number
     */
    @NonNull
    public static Polynomial fromValue(
            @NonNull final Random random, @NonNull final FieldElement fixedValue, final int degree) {

        Objects.requireNonNull(random, "random must not be null");
        final Field field = Objects.requireNonNull(fixedValue, "fixedValue must not be null")
                .field();
        if (degree <= 0) {
            throw new IllegalArgumentException("degree must be positive");
        }
        final List<FieldElement> coefficients = new ArrayList<>(degree + 1);

        // the fixedValue is embedded at x = 0
        coefficients.add(fixedValue);

        for (int i = 0; i < degree; i++) {
            coefficients.add(field.random(random));
        }

        return new Polynomial(coefficients);
    }

    /**
     * Evaluate the polynomial at a given value.
     *
     * @param value the value at which to evaluate the polynomial
     * @return the value of the polynomial at the given value
     */
    @NonNull
    public FieldElement evaluate(final long value) {
        final Field field = coefficients.getFirst().field();
        final FieldElement fieldElement = field.fromLong(value);
        FieldElement result = field.fromLong(0L);
        for (int i = 0; i < coefficients.size(); i++) {
            result = result.add(coefficients.get(i).multiply(fieldElement.power(i)));
        }

        return result;
    }
}
