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

package com.hedera.cryptography.pairings.extensions;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A polynomial where the coefficients are points on the elliptic curve group.
 *
 * @param coefficients the polynomial coefficients.
 */
public record EcPolynomial(@NonNull List<GroupElement> coefficients) {
    /**
     * Constructor.
     *
     * @param coefficients The commitment coefficients.
     */
    public EcPolynomial {
        if (Objects.requireNonNull(coefficients).isEmpty()) {
            throw new IllegalArgumentException("coefficients must not be empty");
        }
    }

    /**
     * Creates a FeldmanCommitment which is a {@link EcPolynomial} where every
     * coefficient consists of the group generator, raised to the power of a coefficient of the {@link FiniteFieldPolynomial} being committed to.
     *
     * @param group      the group that elements of the commitment are in
     * @param finiteFieldPolynomial the polynomial to commit to
     * @return the FeldmanCommitment
     */
    @NonNull
    public static EcPolynomial create(
            @NonNull final Group group, @NonNull final FiniteFieldPolynomial finiteFieldPolynomial) {
        final GroupElement generator = Objects.requireNonNull(group).generator();

        final List<GroupElement> commitmentCoefficients = new ArrayList<>();
        for (final FieldElement polynomialCoefficient :
                Objects.requireNonNull(finiteFieldPolynomial).coefficients()) {
            commitmentCoefficients.add(generator.multiply(polynomialCoefficient));
        }

        return new EcPolynomial(commitmentCoefficients);
    }

    /**
     * Evaluates the polynomial at a specific value without reveling the polynomial.
     *
     * @param x the value to evaluate the commitment
     * @return a point on the curve
     */
    @NonNull
    public GroupElement evaluate(@NonNull final FieldElement x) {

        Objects.requireNonNull(x, "x must not be null");
        int n = coefficients.size() - 1;
        GroupElement result = coefficients.get(n);
        for (int i = n - 1; i >= 0; i--) {
            result = result.multiply(x).add(coefficients.get(i));
        }
        return result;
    }
}
