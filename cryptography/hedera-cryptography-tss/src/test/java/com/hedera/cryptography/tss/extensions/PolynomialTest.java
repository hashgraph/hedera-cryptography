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

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import java.security.SecureRandom;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

// FUTURE maybe use https://github.com/PoslavskySV/rings to match values against another implementation.
class PolynomialTest {

    private static final Random ROOT_RNG = new SecureRandom();

    @Test
    void testNegativeOrZeroDegreeThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> Polynomial.fromValue(Mockito.mock(Random.class), Mockito.mock(FieldElement.class), -1));
        assertThrows(
                IllegalArgumentException.class,
                () -> Polynomial.fromValue(Mockito.mock(Random.class), Mockito.mock(FieldElement.class), 0));
    }

    @Test
    void testNullRandomOrSecretThrowsException() {
        assertThrows(
                NullPointerException.class, () -> Polynomial.fromValue(null, Mockito.mock(FieldElement.class), 10));
        assertThrows(NullPointerException.class, () -> Polynomial.fromValue(Mockito.mock(Random.class), null, 10));
    }

    @Test
    void testEmptyCoefficientsThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> new Polynomial(List.of()));
    }

    @Test
    void testEvaluateEmptyValueThrowsException() {
        assertThrows(NullPointerException.class, () -> new Polynomial(
                        List.of(Mockito.mock(FieldElement.class), Mockito.mock(FieldElement.class)))
                .evaluate(null));
    }

    @Test
    void testEvaluationReturnsNonNull() {
        final long seed = ROOT_RNG.nextLong();
        var rng = new Random(seed);
        System.out.println();
        var curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128).pairingFriendlyCurve();
        final Field field = curve.field();
        var poly = Polynomial.fromValue(rng, field.random(rng), 10);

        var values = IntStream.range(0, 100).boxed().map(i -> field.random(rng)).toList();

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
        var poly = new Polynomial(List.of(freeCoeff, field.fromLong(1), field.fromLong(1), field.fromLong(1)));
        assertEquals(freeCoeff, poly.evaluate(field.fromLong(0)));
        assertEquals(field.fromLong(1).multiply(field.fromLong(poly.degree() + 1)), poly.evaluate(field.fromLong(1)));
    }
}
