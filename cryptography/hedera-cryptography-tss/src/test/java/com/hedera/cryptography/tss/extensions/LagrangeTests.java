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

import static com.hedera.cryptography.tss.extensions.LagrangeTests.Pair.p;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

public class LagrangeTests {

    @Test
    @SuppressWarnings("unchecked")
    void testInvalidInvocationsGroupElementValues() {
        assertThrows(NullPointerException.class, () -> Lagrange.recoverGroupElement(null, null));
        assertThrows(NullPointerException.class, () -> Lagrange.recoverGroupElement(null, mock(List.class)));
        assertThrows(NullPointerException.class, () -> Lagrange.recoverGroupElement(mock(List.class), null));
        assertThrows(IllegalArgumentException.class, () -> Lagrange.recoverGroupElement(mock(List.class), List.of()));
        assertThrows(IllegalArgumentException.class, () -> Lagrange.recoverGroupElement(List.of(), mock(List.class)));
        assertThrows(
                IllegalArgumentException.class,
                () -> Lagrange.recoverGroupElement(
                        List.of(mock(FieldElement.class)),
                        List.of(mock(GroupElement.class), mock(GroupElement.class))));
        assertThrows(
                IllegalArgumentException.class,
                () -> Lagrange.recoverGroupElement(
                        List.of(mock(FieldElement.class), mock(FieldElement.class)),
                        List.of(mock(GroupElement.class))));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testInvalidInvocationsFieldElementValues() {
        assertThrows(NullPointerException.class, () -> Lagrange.recoverFieldElement(null, null));
        assertThrows(NullPointerException.class, () -> Lagrange.recoverFieldElement(null, mock(List.class)));
        assertThrows(NullPointerException.class, () -> Lagrange.recoverFieldElement(mock(List.class), null));
        assertThrows(IllegalArgumentException.class, () -> Lagrange.recoverFieldElement(mock(List.class), List.of()));
        assertThrows(IllegalArgumentException.class, () -> Lagrange.recoverFieldElement(List.of(), mock(List.class)));
        assertThrows(
                IllegalArgumentException.class,
                () -> Lagrange.recoverFieldElement(
                        List.of(mock(FieldElement.class)),
                        List.of(mock(FieldElement.class), mock(FieldElement.class))));
        assertThrows(
                IllegalArgumentException.class,
                () -> Lagrange.recoverFieldElement(
                        List.of(mock(FieldElement.class), mock(FieldElement.class)),
                        List.of(mock(FieldElement.class))));
    }

    @Test
    void testLagrangeWithKnownFieldElementValues() {
        // Calculated using
        // https://www.wolframalpha.com/input?i=interpolating+polynomial+calculator
        var curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128).pairingFriendlyCurve();
        final Field field = curve.field();
        var inputs = inputs(field, 10, 20, 40, 50);
        assertEquals(field.fromLong(10), Lagrange.recoverFieldElement(inputs.xs(), inputs.ys()));
        inputs = inputs(field, 0, 1, 1, 2, 3, 5, 8, 13, 21);
        assertEquals(field.fromLong(0), Lagrange.recoverFieldElement(inputs.xs(), inputs.ys()));
        inputs = inputs(field, 2, 4, 8, 16, 32, 64, 128, 256, 512);
        assertEquals(field.fromLong(2), Lagrange.recoverFieldElement(inputs.xs(), inputs.ys()));
        inputs = inputs(field, p(1, 1), p(4, 4), p(9, 9), p(16, 16));
        assertEquals(field.fromLong(0), Lagrange.recoverFieldElement(inputs.xs(), inputs.ys()));
    }

    @Test
    void testLagrangeWithKnownGroupElementValues() {
        // Calculated using
        // https://www.wolframalpha.com/input?i=interpolating+polynomial+calculator
        var curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128).pairingFriendlyCurve();
        final Field field = curve.field();
        var inputs = inputs(field, 10, 20, 40, 50);
        assertEquals(
                curve.group1().generator().multiply(field.fromLong(10)),
                Lagrange.recoverGroupElement(inputs.xs(), toPoints(curve.group1(), inputs.ys())));
        inputs = inputs(field, 0, 1, 1, 2, 3, 5, 8, 13, 21);
        assertEquals(
                curve.group1().generator().multiply(field.fromLong(0)),
                Lagrange.recoverGroupElement(inputs.xs(), toPoints(curve.group1(), inputs.ys())));
        inputs = inputs(field, 2, 4, 8, 16, 32, 64, 128, 256, 512);
        assertEquals(
                curve.group1().generator().multiply(field.fromLong(2)),
                Lagrange.recoverGroupElement(inputs.xs(), toPoints(curve.group1(), inputs.ys())));
        inputs = inputs(field, p(1, 1), p(4, 4), p(9, 9), p(16, 16));
        assertEquals(
                curve.group1().generator().multiply(field.fromLong(0)),
                Lagrange.recoverGroupElement(inputs.xs(), toPoints(curve.group1(), inputs.ys())));
    }

    private List<GroupElement> toPoints(final Group group, final List<FieldElement> inputs) {
        return inputs.stream().map(i -> group.generator().multiply(i)).toList();
    }

    private Result inputs(final Field field, final Pair... points) {
        var ys = Stream.of(points).map(Pair::y).map(field::fromLong).toList();
        var xs = Stream.of(points).map(Pair::x).map(field::fromLong).toList();
        return new Result(xs, ys);
    }

    private Result inputs(final Field field, final Integer... integers) {
        var ys = Stream.of(integers).map(field::fromLong).toList();
        var xs = IntStream.range(0, ys.size()).boxed().map(field::fromLong).toList();
        return new Result(xs, ys);
    }

    record Pair(int x, int y) {
        static Pair p(final int x, final int y) {
            return new Pair(x, y);
        }
    }

    record Result(List<FieldElement> xs, List<FieldElement> ys) {}
}
