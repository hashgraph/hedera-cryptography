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

package com.hedera.cryptography.pairings.test.extensions;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.extensions.FiniteFieldPolynomial;
import com.hedera.cryptography.pairings.test.fixtures.curve.TestFixtureCurves;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

// FUTURE work:Given that the polynomial is defined for a finite field, it is not possible to easily test it.
// By using an alternative finite field implementation, we can calculate a reference polynomial with the second library
// and contrast the result of the two of them as a testing mechanism.
// possibly investigate: https://github.com/PoslavskySV/rings
@WithRng
class FiniteFieldPolynomialTest {
    private static final PairingFriendlyCurve CURVE =
            PairingFriendlyCurves.findInstance(TestFixtureCurves.NO_PAIRING_CURVE);

    @Test
    void testEmptyCoefficientsThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> new FiniteFieldPolynomial(List.of()));
    }

    @Test
    void testEvaluationReturnsNonNull(final Random rng) {
        var array = new byte[32];
        rng.nextBytes(array);
        var field = CURVE.field();
        var coeff = IntStream.range(0, array.length)
                .mapToObj(i -> field.fromLong(array[i]))
                .toList();
        var poly = new FiniteFieldPolynomial(coeff);
        IntStream.range(0, 100).forEach(i -> assertNotNull(poly.evaluate(i)));
    }

    @Test
    void testEvaluationKnownResults(final Random rng) {
        final Field field = CURVE.field();
        var degree = rng.nextInt(0, Integer.MAX_VALUE);
        final FieldElement freeCoeff = field.fromLong(1);
        final List<FieldElement> freeCoeff1 = Collections.nCopies(degree, freeCoeff);
        var poly = new FiniteFieldPolynomial(freeCoeff1);
        assertEquals(freeCoeff, poly.evaluate(0));
        var result = poly.evaluate(1);
        for (int i = 0; i < degree - 1; i++) {
            result = result.subtract(freeCoeff);
        }
        assertEquals(freeCoeff, result);
    }
}
