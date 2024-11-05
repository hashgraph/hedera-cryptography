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

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.extensions.FiniteFieldPolynomial;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
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

    @Test
    void testNegativeOrZeroDegreeThrowsException() {
        var field = PairingFriendlyCurves.findInstance(Curve.ALT_BN128)
                .pairingFriendlyCurve()
                .field();
        assertThrows(
                IllegalArgumentException.class, () -> FiniteFieldPolynomial.fromValue(ROOT_RNG, field.fromLong(0), -1));
        assertThrows(
                IllegalArgumentException.class, () -> FiniteFieldPolynomial.fromValue(ROOT_RNG, field.fromLong(0), 0));
    }

    @SuppressWarnings("DataFlowIssue")
    @Test
    void testNullRandomOrSecretThrowsException() {
        var field = PairingFriendlyCurves.findInstance(Curve.ALT_BN128)
                .pairingFriendlyCurve()
                .field();
        assertThrows(NullPointerException.class, () -> FiniteFieldPolynomial.fromValue(null, field.fromLong(0), 10));
        assertThrows(NullPointerException.class, () -> FiniteFieldPolynomial.fromValue(ROOT_RNG, null, 10));
    }

    @Test
    void testEmptyCoefficientsThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> new FiniteFieldPolynomial(List.of()));
    }

    @Test
    void testEvaluationReturnsNonNull(final Random rng) {
        var curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128).pairingFriendlyCurve();
        final Field field = curve.field();
        var poly = FiniteFieldPolynomial.fromValue(rng, field.random(rng), 10);

        var values = IntStream.range(0, 100).boxed().toList();

        for (var value : values) {
            assertNotNull(poly.evaluate(value));
        }
    }

    @Test
    void testEvaluationKnownResults() {
        System.out.println();
        var curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128).pairingFriendlyCurve();
        final Field field = curve.field();
        final FieldElement freeCoeff = field.fromLong(1);
        var poly =
                new FiniteFieldPolynomial(List.of(freeCoeff, field.fromLong(1), field.fromLong(1), field.fromLong(1)));
        assertEquals(freeCoeff, poly.evaluate(0));
        assertEquals(field.fromLong(1).multiply(field.fromLong(poly.degree() + 1)), poly.evaluate(1));
    }
}
